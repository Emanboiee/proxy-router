import { defineConfig } from '@playwright/test';
const port = process.env.PLAYWRIGHT_PORT ?? '1420';
export default defineConfig({
  testDir: './tests', workers: 1,
  use: { baseURL: `http://127.0.0.1:${port}`, channel: process.env.PLAYWRIGHT_CHANNEL },
  webServer: {
    command: `npm run dev -- --port ${port}`,
    url: `http://127.0.0.1:${port}`,
    reuseExistingServer: !process.env.PLAYWRIGHT_PORT,
  },
});
