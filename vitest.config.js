import { defineConfig } from 'vitest/config';

// Scope vitest to the unit suite so it does not try to run the Playwright e2e
// specs (which live in e2e/ and import @playwright/test).
export default defineConfig({
  test: {
    include: ['test/**/*.test.js'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
});
