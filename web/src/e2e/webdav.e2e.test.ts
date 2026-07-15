/**
 * WebDAV 适配器集成测试：Node 起真实 WebDAV 服务（webdav-server），
 * safedrive 以 webdav 数据源在其上完成加密上传 → Range 流式解密下载。
 * 运行：E2E=1 pnpm vitest run src/e2e/webdav.e2e.test.ts（前置 cargo build --release）
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore 无类型声明
import { v2 as webdav } from 'webdav-server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const BASE = 'http://127.0.0.1:52670';
const DAV_PORT = 52671;
const BIN = process.env.SAFEDRIVE_BIN ?? join(dirname(fileURLToPath(import.meta.url)), '../../../target/release/safedrive');

let server: ChildProcess;
let davServer: { start: (cb: () => void) => void; stop: (cb: () => void) => void };
let dataDir: string;
let davRoot: string;
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

function testData(n: number): Uint8Array {
  const out = new Uint8Array(n);
  let x = 0x9e3779b9;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}

describe.skipIf(!process.env.E2E && process.env.npm_lifecycle_event !== 'test:e2e')('WebDAV 适配器：真实服务加密全流程', () => {
  beforeAll(async () => {
    davRoot = mkdtempSync(join(tmpdir(), 'sd-dav-'));
    dataDir = mkdtempSync(join(tmpdir(), 'sd-data2-'));

    // 真实 WebDAV 服务（匿名读写）
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
    davServer = new webdav.WebDAVServer({ port: DAV_PORT });
    await new Promise<void>((resolve) => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      (davServer as unknown as { setFileSystem: (p: string, fs: unknown, cb: () => void) => void }).setFileSystem(
        '/',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
        new webdav.PhysicalFileSystem(davRoot),
        () => davServer.start(() => resolve()),
      );
    });

    server = spawn(BIN, ['--bind', '127.0.0.1:52670', '--data-dir', dataDir], { stdio: 'ignore' });
    for (let i = 0; i < 50; i++) {
      try {
        await apiJson('/api/health');
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    await apiJson('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxSplit: 64 * 1024, maxThreads: 6, maxPerVolume: 2 }),
    });
    const ds = await apiJson<{ id: string }>('/api/ds', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'e2e-dav',
        type: 'webdav',
        config: { url: `http://127.0.0.1:${DAV_PORT}`, username: '', password: '' },
        encryptionEnabled: true,
        password: 'e2e-password',
        volumeEnabled: true,
        volumeSize: 128 * 1024,
        volumeStrategy: 'fixed',
        volumeNameFormat: '{s}_{i}.bin',
        cacheEnabled: true,
      }),
    });
    dsId = ds.id;
  }, 30_000);

  afterAll(async () => {
    server?.kill();
    await new Promise<void>((r) => davServer?.stop(() => r()));
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(davRoot, { recursive: true, force: true });
  });

  it('mkdir / upload / list / stream+Range / rename / delete', async () => {
    const test = await post(`/api/ds/${dsId}/test`, {});
    expect(test.ok).toBe(true);

    // 上传 300 KB → 3 个 128 KiB 分卷（最后一卷 44 KB）
    await post(`/api/files/${dsId}/mkdir`, { path: '文档' });
    const original = testData(300 * 1024);
    const up = await fetch(
      `${BASE}/api/files/${dsId}/upload?path=${encodeURIComponent('文档/报告.pdf')}&size=${original.length}`,
      { method: 'PUT', body: original as unknown as BodyInit },
    );
    expect(up.ok).toBe(true);

    // DAV 磁盘形态：无明文，全部加密名
    const davEntries = readdirSync(davRoot);
    expect(davEntries).toHaveLength(1);
    expect(davEntries[0]).not.toContain('文档');
    const inner = readdirSync(join(davRoot, davEntries[0]));
    expect(inner).toHaveLength(1);
    const chunks = readdirSync(join(davRoot, davEntries[0], inner[0]));
    expect(chunks).toHaveLength(3);
    for (const c of chunks) expect(c).toMatch(/^[0-9a-f]{2}$/);

    // list 明文
    const sub = await apiJson<{ entries: { name: string; size: number }[] }>(
      `/api/files/${dsId}/list?path=${encodeURIComponent('文档')}`,
    );
    expect(sub.entries).toHaveLength(1);
    expect(sub.entries[0]).toMatchObject({ name: '报告.pdf', size: original.length });

    // /stream 全量（经 WebDAV Range 并行拉取 + 解密）
    const full = await fetch(`${BASE}/stream/${dsId}/${encodeURIComponent('文档')}/${encodeURIComponent('报告.pdf')}`);
    expect(full.status).toBe(200);
    expect(new Uint8Array(await full.arrayBuffer())).toEqual(original);

    // Range 跨分卷
    const part = await fetch(
      `${BASE}/stream/${dsId}/${encodeURIComponent('文档')}/${encodeURIComponent('报告.pdf')}`,
      { headers: { Range: 'bytes=130000-140000' } },
    );
    expect(part.status).toBe(206);
    expect(new Uint8Array(await part.arrayBuffer())).toEqual(original.subarray(130000, 140001));

    // rename + 再下载
    await post(`/api/files/${dsId}/rename`, { from: '文档/报告.pdf', to: '文档/终稿.pdf' });
    const renamed = await fetch(
      `${BASE}/stream/${dsId}/${encodeURIComponent('文档')}/${encodeURIComponent('终稿.pdf')}`,
    );
    expect(renamed.status).toBe(200);
    expect(new Uint8Array(await renamed.arrayBuffer())).toEqual(original);

    // delete 递归
    await post(`/api/files/${dsId}/delete`, { path: '文档' });
    expect(readdirSync(davRoot)).toHaveLength(0);
  }, 60_000);
});
