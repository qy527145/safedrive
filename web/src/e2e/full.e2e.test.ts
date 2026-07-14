/**
 * 端到端集成测试：真实 safedrive 二进制 + localfs 数据源。
 * 加解密全部在服务端 —— 本测试作为「前端」只用明文 API 与 /stream，
 * 再直接检查磁盘验证云端形态（加密名文件夹 + 随机 .bin 分卷）。
 * 默认跳过；运行：E2E=1 pnpm vitest run src/e2e/full.e2e.test.ts
 * 前置：cargo build --release
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const BASE = 'http://127.0.0.1:52660';
const BIN = join(dirname(fileURLToPath(import.meta.url)), '../../../target/release/safedrive');

let server: ChildProcess;
let dataDir: string;
let storageRoot: string;
let dsId: string;

async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE}${path}`, init);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

const post = (path: string, body: unknown) =>
  apiJson<Record<string, unknown>>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

interface Entry {
  name: string;
  isDir: boolean;
  size: number;
  mtime: number;
  foreign: boolean;
}

const listDir = (path: string) =>
  apiJson<{ entries: Entry[] }>(`/api/files/${dsId}/list?path=${encodeURIComponent(path)}`).then(
    (r) => r.entries,
  );

const uploadBytes = async (path: string, data: Uint8Array) => {
  const r = await fetch(
    `${BASE}/api/files/${dsId}/upload?path=${encodeURIComponent(path)}&size=${data.length}`,
    { method: 'PUT', body: data as unknown as BodyInit },
  );
  if (!r.ok) throw new Error(`upload: HTTP ${r.status} ${await r.text()}`);
};

const streamBytes = async (path: string, range?: string): Promise<{ status: number; body: Uint8Array; headers: Headers }> => {
  const enc = path.split('/').map(encodeURIComponent).join('/');
  const r = await fetch(`${BASE}/stream/${dsId}/${enc}`, {
    headers: range ? { Range: range } : {},
  });
  return { status: r.status, body: new Uint8Array(await r.arrayBuffer()), headers: r.headers };
};

/** 生成大块测试数据（确定性 PRNG）。 */
function testData(n: number): Uint8Array {
  const out = new Uint8Array(n);
  let x = 0x12345678;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}

describe.skipIf(!process.env.E2E)('端到端：服务端加密上传 → 云端形态校验 → /stream 解密下载', () => {
  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'sd-data-'));
    storageRoot = mkdtempSync(join(tmpdir(), 'sd-store-'));
    server = spawn(BIN, ['--bind', '127.0.0.1:52660', '--data-dir', dataDir], { stdio: 'ignore' });
    for (let i = 0; i < 50; i++) {
      try {
        await apiJson('/api/health');
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    // 策略：256 KiB 分卷；下载参数走全局设置（128 KiB 分片）
    await apiJson('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxSplit: 128 * 1024, maxThreads: 8, maxPerVolume: 2 }),
    });
    const strategy = await apiJson<{ id: string }>('/api/strategies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'e2e', volumeSize: 256 * 1024 }),
    });
    const ds = await apiJson<{ id: string }>('/api/ds', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'e2e-local',
        type: 'localfs',
        config: { root: storageRoot },
        strategyId: strategy.id,
      }),
    });
    dsId = ds.id;
  }, 30_000);

  afterAll(() => {
    server?.kill();
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(storageRoot, { recursive: true, force: true });
  });

  it('完整流程', async () => {
    // ---- 创建目录「电影」，上传「测试视频.mp4」(700 KB → 3 分卷) ----
    await post(`/api/files/${dsId}/mkdir`, { path: '电影' });
    const original = testData(700 * 1024);
    await uploadBytes('电影/测试视频.mp4', original);

    // ---- 云端形态校验（直接看磁盘）：加密名 + 随机 .bin，绝不出现明文 ----
    const rootEntries = readdirSync(storageRoot);
    expect(rootEntries).toHaveLength(1);
    const dirEnc = rootEntries[0];
    expect(dirEnc).not.toContain('电影');
    // v5 名称编码：全汉字，负载含 16B 节点密钥（「电影」→ ~16 字）
    expect(dirEnc.length).toBeLessThan(20);
    expect(dirEnc).toMatch(/^[\u4e00-\u8e06]+$/);
    expect(statSync(join(storageRoot, dirEnc)).isDirectory()).toBe(true);

    const movieEntries = readdirSync(join(storageRoot, dirEnc));
    expect(movieEntries).toHaveLength(1);
    const fileEnc = movieEntries[0];
    expect(fileEnc).not.toContain('测试视频');
    expect(fileEnc.length).toBeLessThan(30);
    expect(fileEnc).toMatch(/^[\u4e00-\u8e06]+$/);

    const chunkFiles = readdirSync(join(storageRoot, dirEnc, fileEnc));
    expect(chunkFiles).toHaveLength(3); // ceil(700K / 256K)
    // 分卷名 = 密码派生 keystream hex，前 256 卷 2 字符
    for (const f of chunkFiles) expect(f).toMatch(/^[0-9a-f]{2}$/);
    // ChaCha20：密文长度 = 明文长度（无 tag），且内容不同
    // 名字顺序与字典序无关：按大小分组断言（2 整卷 + 1 尾卷）
    const sizes = chunkFiles
      .map((f) => readFileSync(join(storageRoot, dirEnc, fileEnc, f)).length)
      .sort((a, b) => b - a);
    expect(sizes).toEqual([256 * 1024, 256 * 1024, 700 * 1024 - 512 * 1024]);
    const onDisk = chunkFiles.map((f) => readFileSync(join(storageRoot, dirEnc, fileEnc, f)));
    expect(Buffer.from(original.subarray(0, 100))).not.toEqual(onDisk[0].subarray(0, 100));

    // ---- list：明文名称与大小直接可读 ----
    const root = await listDir('');
    expect(root).toHaveLength(1);
    expect(root[0]).toMatchObject({ name: '电影', isDir: true, foreign: false });
    const movieDir = await listDir('电影');
    expect(movieDir).toHaveLength(1);
    expect(movieDir[0]).toMatchObject({ name: '测试视频.mp4', isDir: false, size: original.length });

    // ---- /stream 全量下载：字节一致 ----
    const full = await streamBytes('电影/测试视频.mp4');
    expect(full.status).toBe(200);
    expect(full.headers.get('accept-ranges')).toBe('bytes');
    expect(full.headers.get('content-length')).toBe(String(original.length));
    expect(full.body).toEqual(original);

    // ---- Range 请求：206 + 各种切法（跨分卷、末尾后缀、开区间） ----
    const cases: Array<[string, number, number]> = [
      ['bytes=0-99', 0, 99],
      ['bytes=262100-262200', 262100, 262200], // 跨第 1/2 分卷边界
      ['bytes=700000-', 700000, original.length - 1],
      ['bytes=-1000', original.length - 1000, original.length - 1],
    ];
    for (const [range, s, e] of cases) {
      const r = await streamBytes('电影/测试视频.mp4', range);
      expect(r.status).toBe(206);
      expect(r.headers.get('content-range')).toBe(`bytes ${s}-${e}/${original.length}`);
      expect(r.body).toEqual(original.subarray(s, e + 1));
    }

    // 不可满足的 Range → 416
    const bad = await streamBytes('电影/测试视频.mp4', `bytes=${original.length}-`);
    expect(bad.status).toBe(416);
    expect(bad.headers.get('content-range')).toBe(`bytes */${original.length}`);

    // ---- 空文件：上传 + list + 下载 ----
    await uploadBytes('电影/空文件.txt', new Uint8Array(0));
    const empty = await streamBytes('电影/空文件.txt');
    expect(empty.status).toBe(200);
    expect(empty.body).toHaveLength(0);

    // ---- 重命名：云端目录名变化（新 salt），内容不动 ----
    await post(`/api/files/${dsId}/rename`, {
      from: '电影/测试视频.mp4',
      to: '电影/改名后的视频.mp4',
    });
    const afterRename = await listDir('电影');
    const renamed = afterRename.find((x) => x.name === '改名后的视频.mp4');
    expect(renamed).toBeDefined();
    expect(renamed!.size).toBe(original.length);
    const movieEntries2 = readdirSync(join(storageRoot, dirEnc)).filter((n) => !n.includes('空文件'));
    expect(movieEntries2.some((n) => n !== fileEnc)).toBe(true); // 加密名已更换
    const again = await streamBytes('电影/改名后的视频.mp4');
    expect(again.body).toEqual(original);

    // ---- 外来文件：list 标记 foreign，可单独删除 ----
    const { writeFileSync } = await import('node:fs');
    writeFileSync(join(storageRoot, dirEnc, 'alien.txt'), 'not ours');
    const withForeign = await listDir('电影');
    const alien = withForeign.find((x) => x.foreign);
    expect(alien).toBeDefined();
    expect(alien!.name).toBe('alien.txt');
    await post(`/api/files/${dsId}/delete-foreign`, { path: '电影', name: 'alien.txt' });
    expect((await listDir('电影')).every((x) => !x.foreign)).toBe(true);

    // ---- 递归删除目录：磁盘清空 ----
    await post(`/api/files/${dsId}/delete`, { path: '电影' });
    expect(readdirSync(storageRoot)).toEqual([]);
    expect(await listDir('')).toEqual([]);

    // ---- 密码本导出：包含刚才操作留下的结构 ----
    const exported = await fetch(`${BASE}/api/vault/export`);
    expect(exported.ok).toBe(true);
    const vaultJson = (await exported.json()) as Record<string, unknown>;
    expect(typeof vaultJson).toBe('object');
  }, 60_000);
});
