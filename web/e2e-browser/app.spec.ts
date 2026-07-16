/**
 * 浏览器级 E2E（真实 Chromium + 真实二进制，加解密全在服务端）：
 * 建数据源 → 上传 → 云端形态校验 → 刷新 → /stream 预览 →
 * 原生下载字节比对 → 重命名 → 删除。
 * 运行：npx playwright test（前置 cargo build --release && pnpm build）
 */

import { expect, test } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE = 'http://127.0.0.1:52680';
const BIN = process.env.SAFEDRIVE_BIN ?? join(dirname(fileURLToPath(import.meta.url)), '../../target/release/safedrive');
const MARKER = 'UNIQUE_MARKER_XYZ_20260713';

let server: ChildProcess;
let dataDir: string;
let storageRoot: string;
let uploadFile: string;
let originalContent: string;

test.beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'sd-ui-data-'));
  storageRoot = mkdtempSync(join(tmpdir(), 'sd-ui-store-'));
  // ~300KB 文本，首行含唯一标记
  originalContent = `第一行内容 ${MARKER}\n` + `这是测试文件的填充内容，用于验证端到端加密。\n`.repeat(4500);
  uploadFile = join(mkdtempSync(join(tmpdir(), 'sd-ui-src-')), 'hello.txt');
  writeFileSync(uploadFile, originalContent);

  server = spawn(BIN, ['--bind', '127.0.0.1:52680', '--data-dir', dataDir], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  server.stderr!.on('data', (d: Buffer) => (stderr += d.toString()));
  let healthy = false;
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/api/health`);
      if (r.ok) {
        healthy = true;
        break;
      }
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!healthy) throw new Error(`服务端启动失败（端口可能被占用）：${stderr}`);
});

test.afterAll(() => {
  server?.kill('SIGKILL');
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(storageRoot, { recursive: true, force: true });
});

test('完整 UI 流程：数据源 → 上传 → 预览/下载 → 重命名 → 删除', async ({ page }) => {
  // ---- 无密码模式直接进入主界面 ----
  await page.goto('/');
  await expect(page.getByText('数据管理')).toBeVisible({ timeout: 30_000 });
  const frameBefore = await page.locator('.page-frame').boundingBox();
  await page.waitForTimeout(800); // 覆盖多次 250ms 实时速度刷新
  const frameAfter = await page.locator('.page-frame').boundingBox();
  expect(frameAfter?.x).toBe(frameBefore?.x);
  expect(frameAfter?.width).toBe(frameBefore?.width);

  // ---- 设置页：全局传输参数可见 ----
  await page.getByText('设置', { exact: true }).click();
  await expect(page.getByLabel('最大分片大小')).toBeVisible();
  await expect(page.getByLabel('下载线程数')).toBeVisible();
  await expect(page.getByLabel('单分卷最大并发线程数')).toBeVisible();

  // ---- 创建数据源（已融合进数据管理页） ----
  await page.getByRole('menuitem', { name: '数据管理' }).click();
  await page.getByRole('button', { name: '添加数据源' }).first().click();
  await page.getByLabel('数据源名称').fill('本地测试');
  await page.locator('.ant-form-item').filter({ hasText: '根目录' }).locator('input').fill(storageRoot);
  await page.getByLabel('根密码').fill('e2e-password');
  await page.getByRole('button', { name: /确\s*定/ }).click();
  await expect(page.locator('.source-card').filter({ hasText: '本地测试' })).toBeVisible({ timeout: 15_000 });

  // ---- 进入浏览器并上传 ----
  await page.locator('.source-card').filter({ hasText: '本地测试' }).locator('.ant-card-meta-title').click();
  await expect(page.locator('.ant-breadcrumb').getByText('根目录')).toBeVisible();
  await page.locator('input[type=file]').first().setInputFiles(uploadFile);
  await expect(page.getByText('hello.txt')).toBeVisible({ timeout: 30_000 });

  // ---- 云端形态：只有加密名文件夹 + 随机 .bin，且名称短（v5 全汉字编码，密钥入名） ----
  const rootEntries = readdirSync(storageRoot);
  expect(rootEntries).toHaveLength(1);
  expect(rootEntries[0]).not.toContain('hello');
  expect(rootEntries[0].length).toBeLessThan(28);
  expect(rootEntries[0]).toMatch(/^[\u3400-\u4dbf\u4e00-\u9fff]+$/);
  const chunks = readdirSync(join(storageRoot, rootEntries[0]));
  expect(chunks.length).toBeGreaterThan(0);
  for (const c of chunks) expect(c).toMatch(/^[0-9a-f]{2}$/);
  const cipherHead = readFileSync(join(storageRoot, rootEntries[0], chunks[0])).subarray(0, 200);
  expect(cipherHead.includes(Buffer.from(MARKER))).toBe(false);

  // ---- 刷新后无需任何解锁，直接可用 ----
  await page.reload();
  await expect(page.getByText('数据管理')).toBeVisible({ timeout: 30_000 });
  await page.getByRole('menuitem', { name: '数据管理' }).click();
  await page.locator('.source-card').filter({ hasText: '本地测试' }).locator('.ant-card-meta-title').click();
  await expect(page.getByText('hello.txt')).toBeVisible({ timeout: 15_000 });

  // ---- /stream 文本预览：服务端解密后的首行可见 ----
  await page.getByText('hello.txt').click();
  await expect(page.getByText(MARKER)).toBeVisible({ timeout: 30_000 });
  await page.locator('.ant-modal-close').click();
  await expect(page.locator('.ant-modal-wrap')).toBeHidden();

  // ---- 原生下载（<a href=/stream?dl=1>）：字节级一致 ----
  const row = page.getByRole('row', { name: /hello\.txt/ });
  const dlPromise = page.waitForEvent('download');
  await row.locator('.anticon-download').click();
  const dl = await dlPromise;
  const saved = await dl.path();
  expect(readFileSync(saved!, 'utf8')).toBe(originalContent);

  // ---- 重命名 ----
  await row.locator('.anticon-edit').click();
  await page.locator('.ant-modal input').fill('renamed.txt');
  await page.getByRole('button', { name: /确\s*定/ }).click();
  await expect(page.getByText('renamed.txt')).toBeVisible({ timeout: 15_000 });

  // ---- 删除 ----
  await page.getByRole('row', { name: /renamed\.txt/ }).locator('.anticon-delete').click();
  await page.getByRole('button', { name: /确\s*定/ }).click();
  await expect(page.getByRole('row', { name: /renamed\.txt/ })).toBeHidden({ timeout: 15_000 });
  await expect.poll(() => readdirSync(storageRoot).length, { timeout: 10_000 }).toBe(0);
});
