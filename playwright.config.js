import { defineConfig, devices } from '@playwright/test';

/**
 * E2E config for the relay viewer. Playwright boots `wrangler dev` (local
 * Worker, no Cloudflare account needed) and runs the specs in e2e/ against it.
 * Kept separate from the vitest unit suite (test/*.test.js).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:8787',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npx wrangler dev --ip 127.0.0.1 --port 8787 --log-level error',
    url: 'http://127.0.0.1:8787/view',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    env: { WRANGLER_SEND_METRICS: 'false' },
  },
});
