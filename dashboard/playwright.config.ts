import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests', workers: 1,
  use: { baseURL: 'http://127.0.0.1:1420', channel: process.env.PLAYWRIGHT_CHANNEL },
  webServer: { command: 'npm run dev', url: 'http://127.0.0.1:1420', reuseExistingServer: true },
});
