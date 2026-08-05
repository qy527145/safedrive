/**
 * 服务端 API 客户端。加解密全部在 Rust 服务端完成，前端只与明文
 * 路径打交道 —— 这是一个普通 CRUD 客户端。
 */

export type DsType = 'localfs' | 'webdav' | 'baidupan' | 'aliyundrive' | 'quark';

export interface DsRecord {
  id: string;
  name: string;
  type: DsType;
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
  /** WebDAV 服务开关（/dav 数据平面） */
  webdavEnabled: boolean;
  /** WebDAV 专用账号（留空 = 任意用户名） */
  webdavUsername: string;
  /** WebDAV 专用密码（留空 = 沿用管理密码鉴权） */
  webdavPassword: string;
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
  /** true = 无法解密的外来条目（可删除；受管格式的可输入原密码解密纳管） */
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
  shareApiBase?: string;
  /** 阿里云盘：内置第三方应用键，或 custom（自备 client_id/secret） */
  app?: string;
  /** 阿里云盘：resource（资源盘）/ backup（备份盘） */
  driveType?: string;
  /** 阿里云盘：开放平台接口地址，留空用默认 */
  apiBase?: string;
  driveId?: string;
  /** 阿里云盘：官网令牌（可选），配了才支持分享/转存 */
  webRefreshToken?: string;
  webAccessToken?: string;
  webAccessTokenExpiresAt?: number;
  /** 夸克网盘：浏览器 Cookie 全串 */
  cookie?: string;
}
export type DsInput = Omit<DsRecord, 'id' | 'createdAt' | 'password'> & { password?: string };

/** 内置的阿里云盘第三方应用：扫码与刷新走该应用作者的中转服务，用户不必自备应用。 */
export interface AliyunApp {
  key: string;
  name: string;
  clientId: string;
  /** 提示文案：这个应用的令牌由谁签发/刷新 */
  note: string;
}

/** 开放平台应用入参。app 省略即默认内置应用；custom 时才需要 client 凭据。 */
export interface AliyunAppInput {
  app?: string;
  clientId?: string;
  clientSecret?: string;
}

/** 官网扫码会话（passport Cookie + 二维码参数）。前端只负责原样带回，不解读。 */
export type AliyunWebSession = Record<string, unknown>;

/** 一次跨数据源复制的成绩单。mode 直接决定 UI 上说「秒传」还是「普通传输」。 */
export interface CopyReport {
  mode: 'rapid' | 'transfer' | 'mixed' | 'empty';
  files: number;
  dirs: number;
  /** 云端直接引用、零字节落地的分卷数 */
  rapidVolumes: number;
  /** 真实搬了字节的分卷数 */
  transferredVolumes: number;
  rapidBytes: number;
  transferredBytes: number;
  /** 因为源/目标加密设置不同而解密重加密的文件数 */
  reencryptedFiles: number;
  skipped: string[];
}

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
  /** 切换阿里云盘盘位（resource 资源库 / backup 备份盘）；服务端会丢弃旧 driveId、清缓存并在新盘按需建根目录。 */
  setDsDrive: (id: string, driveType: 'resource' | 'backup') =>
    request<{ ok: boolean; driveType: string }>(`/api/ds/${id}/drive`, {
      method: 'POST',
      body: JSON.stringify({ driveType }),
    }),
  /** 生成 sdds:// 配置分享链接（包含凭证与根密码，链接即密钥）。 */
  shareDs: (id: string) =>
    request<{ link: string }>(`/api/ds/${id}/share`, { method: 'POST' }),
  /** 通过 sdds:// 链接导入数据源，重名时服务端自动追加序号。 */
  importDs: (link: string) =>
    request<DsRecord>('/api/ds/import', { method: 'POST', body: JSON.stringify({ link }) }),

  // ---- 百度网盘扫码登录（自动获取 BDUSS） ----
  baiduQrCreate: () =>
    request<{ sign: string; gid: string; img: string }>('/api/baidu/qrcode', { method: 'POST' }),
  baiduQrPoll: (sign: string, gid: string) =>
    request<{ status: 'waiting' | 'scanned' | 'confirmed' | 'expired'; bduss?: string }>(
      '/api/baidu/qrcode/poll',
      { method: 'POST', body: JSON.stringify({ sign, gid }) },
    ),

  // ---- 阿里云盘扫码授权（自动获取 refreshToken） ----
  /** 内置第三方应用清单；default 是扫码默认用的应用，custom 是「自备应用」的键。 */
  aliyunApps: () =>
    request<{ apps: AliyunApp[]; default: string; custom: string }>('/api/aliyun/apps'),
  /**
   * 校验手填的 refresh_token：valid=验签通过（确是开放平台令牌），expired=已过期，
   * app 为识别到的内置应用键（null 即认不出，需自填 client_id/secret）。
   */
  aliyunDetect: (refreshToken: string) =>
    request<{
      valid: boolean;
      expired: boolean;
      expiresAt?: number | null;
      app: string | null;
      name?: string;
      note?: string;
    }>('/api/aliyun/detect', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    }),
  aliyunQrCreate: (app: AliyunAppInput) =>
    request<{ app: string; appName: string; qrCodeUrl: string; sid: string; img: string }>(
      '/api/aliyun/qrcode',
      { method: 'POST', body: JSON.stringify(app) },
    ),
  aliyunQrPoll: (app: AliyunAppInput & { sid: string }) =>
    request<{
      status: 'waiting' | 'scanned' | 'confirmed' | 'expired';
      app?: string;
      refreshToken?: string;
      accessToken?: string;
      accessTokenExpiresAt?: number;
    }>('/api/aliyun/qrcode/poll', { method: 'POST', body: JSON.stringify(app) }),
  /**
   * 用官网令牌静默授权第三方应用，免扫码换开放平台 refresh_token。
   * app 省略即默认内置应用（阿里云盘TV）。
   */
  aliyunSilent: (webRefreshToken: string, app?: AliyunAppInput) =>
    request<{ app: string; appName: string; refreshToken: string; accessToken?: string; accessTokenExpiresAt?: number }>(
      '/api/aliyun/silent',
      { method: 'POST', body: JSON.stringify({ webRefreshToken, ...app }) },
    ),

  // ---- 阿里云盘官网扫码（可选令牌，分享/转存专用） ----
  /** 官网二维码是纯文本，由前端自己渲染；session 无状态，轮询时原样带回。 */
  aliyunWebQrCreate: () =>
    request<{ codeContent: string; session: AliyunWebSession }>('/api/aliyun/web/qrcode', {
      method: 'POST',
    }),
  aliyunWebQrPoll: (session: AliyunWebSession) =>
    request<{
      status: 'waiting' | 'scanned' | 'confirmed' | 'expired';
      webRefreshToken?: string;
    }>('/api/aliyun/web/qrcode/poll', { method: 'POST', body: JSON.stringify({ session }) }),

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
  /**
   * 复制（可跨数据源）。两端加密设置一致时逐个分卷原样搬运，能秒传就
   * 秒传；否则解密重加密。返回的 report 说明实际走了哪条路。
   */
  copyPath: (
    ds: string,
    path: string,
    destDs: string,
    destPath: string,
    opts?: { overwrite?: boolean; progress?: string },
  ) =>
    request<{ ok: boolean; report: CopyReport }>(`/api/files/${ds}/copy`, {
      method: 'POST',
      body: JSON.stringify({
        path,
        destDs,
        destPath,
        overwrite: opts?.overwrite ?? false,
        progress: opts?.progress,
      }),
    }).then((r) => r.report),
  deleteForeign: (ds: string, path: string, name: string) =>
    request<{ ok: boolean }>(`/api/files/${ds}/delete-foreign`, {
      method: 'POST',
      body: JSON.stringify({ path, name }),
    }),
  /** 用条目原加密密码（f_key）解密外来条目，并改用当前链路密码重新封装名字。 */
  adoptForeign: (ds: string, path: string, name: string, password: string) =>
    request<{ ok: boolean; name: string; isDir: boolean }>(`/api/files/${ds}/adopt-foreign`, {
      method: 'POST',
      body: JSON.stringify({ path, name, password }),
    }),
  /**
   * 生成分享。native=true 走云盘官网原生分享（返回短链 + 提取码，仅未加密数据源可用）；
   * 否则生成 SafeDrive 标准 sd:// 链接（含解密信息，接收方需 SafeDrive）。
   * password 仅原生分享有效：留空随机生成，填 4 位字母数字则作自定义提取码。
   */
  createShare: (ds: string, paths: string[], native = false, password = '') =>
    request<
      | { native: false; link: string }
      | { native: true; url: string; password: string; quick?: boolean }
    >(`/api/files/${ds}/share`, {
      method: 'POST',
      body: JSON.stringify({ paths, native, password }),
    }),
  /**
   * 导入分享。sd:// 标准链接自带密码；云盘官网原生短链的提取码优先从链接里的
   * `?pwd=`/`?passcode=` 读取，读不到且分享需要密码时后端回 needPassword，由前端
   * 补填后重试。foreign=true 表示明文内容进了加密数据源，将以外来条目呈现。
   */
  importShare: (ds: string, link: string, dir: string, force = false, password = '') =>
    request<{ ok: boolean; imported: number; foreign?: boolean; needPassword?: boolean }>(
      `/api/files/${ds}/import`,
      {
        method: 'POST',
        body: JSON.stringify({ link, dir, force, password }),
      },
    ),
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
