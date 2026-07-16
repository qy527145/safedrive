/**
 * 服务端 API 客户端。加解密全部在 Rust 服务端完成，前端只与明文
 * 路径打交道 —— 这是一个普通 CRUD 客户端。
 */

export interface DsRecord {
  id: string;
  name: string;
  type: 'localfs' | 'webdav' | 'baidupan';
  config: DsConfig;
  encryptionEnabled: boolean;
  password: string;
  volumeEnabled: boolean;
  volumeSize: number;
  volumeStrategy: 'fixed' | 'random';
  volumeNameFormat: string;
  cacheEnabled: boolean;
  createdAt: number;
}

export interface TransferSettings {
  /** 下载分片大小（字节） */
  maxSplit: number;
  /** 下载总线程数 */
  maxThreads: number;
  /** 单分卷并发 */
  maxPerVolume: number;
  /** 全局持久密文块缓存 */
  cacheEnabled: boolean;
}

export interface CacheStats {
  entries: number;
  bytesCached: number;
  hits: number;
  misses: number;
}

export interface FsEntry {
  name: string;
  isDir: boolean;
  size: number;
  mtime: number;
  /** true = 无法解密的外来条目（仅可删除） */
  foreign: boolean;
  cache?: FileCacheStatus;
  downloadSpeed: number;
}
export interface DsConfig {
  [key: string]: string | number | undefined;
  root?: string;
  url?: string;
  username?: string;
  password?: string;
  bduss?: string;
  userAgent?: string;
  clientId?: string;
  clientSecret?: string;
  accessToken?: string;
  refreshToken?: string;
  accessTokenExpiresAt?: number;
}
export type DsInput = Omit<DsRecord, 'id' | 'createdAt' | 'password'> & { password?: string };

export interface FileCacheStatus {
  cached: boolean;
  bytesCached: number;
  totalSize: number;
  complete: boolean;
  /** 手动触发的后台缓存进行中（可停止）。播放/下载的写透缓存不受此标志影响 */
  warming: boolean;
  /** ≤128 个桶，每桶为该区段已缓存块的百分比 0-100（缓存分布热力条） */
  bitmapSummary: number[];
}

export interface TransferSnapshot {
  uploadSpeed: number;
  downloadSpeed: number;
  fileDownloadSpeeds: Record<string, number>;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let token: string | null = localStorage.getItem('sd.token');
let onUnauthorized: (() => void) | null = null;

export function setToken(t: string | null) {
  token = t;
  if (t) localStorage.setItem('sd.token', t);
  else localStorage.removeItem('sd.token');
}

export function getToken(): string | null {
  return token;
}

export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init?.body && typeof init.body === 'string') {
    headers.set('Content-Type', 'application/json');
  }
  const resp = await fetch(path, { ...init, headers });
  if (resp.status === 401) {
    onUnauthorized?.();
    throw new ApiError(401, '未登录或登录已过期');
  }
  if (!resp.ok) {
    let msg = `请求失败 (${resp.status})`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data.error) msg = data.error;
    } catch {
      /* 保留默认消息 */
    }
    throw new ApiError(resp.status, msg);
  }
  const ct = resp.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) return (await resp.json()) as T;
  return (await resp.arrayBuffer()) as unknown as T;
}

/** /stream 播放/下载地址（外部播放器可直接使用；登录模式下带 ?token=）。 */
export function streamUrl(dsId: string, path: string, opts?: { dl?: boolean }): string {
  const enc = path.split('/').map(encodeURIComponent).join('/');
  const params = new URLSearchParams();
  if (opts?.dl) params.set('dl', '1');
  if (token) params.set('token', token);
  const qs = params.toString();
  return `/stream/${dsId}/${enc}${qs ? `?${qs}` : ''}`;
}

export const api = {
  health: () =>
    request<{ name: string; version: string; auth: boolean }>('/api/health'),
  login: (password: string) =>
    request<{ token: string | null }>('/api/login', {
      method: 'POST',
      body: JSON.stringify({ password }),
    }),

  // ---- 数据源 ----
  listDs: () => request<DsRecord[]>('/api/ds'),
  createDs: (body: DsInput) =>
    request<DsRecord>('/api/ds', { method: 'POST', body: JSON.stringify(body) }),
  updateDs: (id: string, body: DsInput) =>
    request<DsRecord>(`/api/ds/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  deleteDs: (id: string) => request<{ ok: boolean }>(`/api/ds/${id}`, { method: 'DELETE' }),
  testDs: (id: string) =>
    request<{ ok: boolean; entries: number }>(`/api/ds/${id}/test`, { method: 'POST' }),

  getSettings: () => request<TransferSettings>('/api/settings'),
  updateSettings: (body: TransferSettings) =>
    request<TransferSettings>('/api/settings', { method: 'PUT', body: JSON.stringify(body) }),
  getCacheStats: () => request<CacheStats>('/api/cache'),
  clearCache: () => request<{ ok: boolean; freed: number }>('/api/cache', { method: 'DELETE' }),
  transferStatus: () => request<TransferSnapshot>('/api/transfers'),

  // ---- 文件（明文路径） ----
  listFiles: (ds: string, path: string) =>
    request<{ entries: FsEntry[] }>(
      `/api/files/${ds}/list?path=${encodeURIComponent(path)}`,
    ).then((r) => r.entries),
  mkdir: (ds: string, path: string) =>
    request<{ ok: boolean }>(`/api/files/${ds}/mkdir`, {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  rename: (ds: string, from: string, to: string) =>
    request<{ ok: boolean }>(`/api/files/${ds}/rename`, {
      method: 'POST',
      body: JSON.stringify({ from, to }),
    }),
  deletePath: (ds: string, path: string) =>
    request<{ ok: boolean }>(`/api/files/${ds}/delete`, {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  deleteForeign: (ds: string, path: string, name: string) =>
    request<{ ok: boolean }>(`/api/files/${ds}/delete-foreign`, {
      method: 'POST',
      body: JSON.stringify({ path, name }),
    }),
  fileCacheStatus: (ds: string, path: string) =>
    request<FileCacheStatus>(`/api/files/${ds}/cache?path=${encodeURIComponent(path)}`),
  clearFileCache: (ds: string, path: string) =>
    request<{ ok: boolean; freed: number }>(
      `/api/files/${ds}/cache?path=${encodeURIComponent(path)}`, { method: 'DELETE' }),
  warmFileCache: (ds: string, path: string) =>
    request<{ ok: boolean; complete: boolean; warming?: boolean }>(
      `/api/files/${ds}/cache?path=${encodeURIComponent(path)}`, { method: 'POST' }),
  stopWarmFileCache: (ds: string, path: string) =>
    request<{ ok: boolean; stopped: boolean }>(
      `/api/files/${ds}/cache/warm?path=${encodeURIComponent(path)}`, { method: 'DELETE' }),

  // ---- 上传双维度进度（encrypted = 本地已加密，uploaded = 远端已确认） ----
  uploadProgress: (id: string) =>
    request<{ total: number; encrypted: number; uploaded: number }>(
      `/api/uploads/${encodeURIComponent(id)}/progress`,
    ),
};

/**
 * XHR 流式上传（fetch 无上传进度事件）。返回可取消句柄。
 * `progressId` 会透传给服务端，供 api.uploadProgress 轮询真实上传进度。
 */
export function uploadFile(
  ds: string,
  path: string,
  file: File,
  onProgress: (sent: number) => void,
  progressId?: string,
): { promise: Promise<void>; cancel: () => void } {
  const xhr = new XMLHttpRequest();
  const promise = new Promise<void>((resolve, reject) => {
    let url = `/api/files/${ds}/upload?path=${encodeURIComponent(path)}&size=${file.size}`;
    if (progressId) url += `&progress=${encodeURIComponent(progressId)}`;
    xhr.open('PUT', url);
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.upload.onprogress = (e) => onProgress(e.loaded);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
        return;
      }
      let msg = `上传失败 (${xhr.status})`;
      try {
        const data = JSON.parse(xhr.responseText) as { error?: string };
        if (data.error) msg = data.error;
      } catch {
        /* 保留默认消息 */
      }
      reject(new ApiError(xhr.status, msg));
    };
    xhr.onerror = () => reject(new ApiError(0, '网络错误'));
    xhr.onabort = () => reject(new ApiError(0, '已取消'));
    xhr.send(file);
  });
  return { promise, cancel: () => xhr.abort() };
}
