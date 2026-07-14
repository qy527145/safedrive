import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e-browser',
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: 'http://127.0.0.1:52680',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
