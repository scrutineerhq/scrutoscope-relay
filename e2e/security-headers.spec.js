import { test, expect } from '@playwright/test';

/**
 * Integration check that the *served* responses carry the security posture the
 * unit tests assert at the function level — the CSP nonce on the viewer, the
 * script-src 'none' fallback everywhere else, and the static security headers.
 */

test.describe('served security headers', () => {
  test('the viewer carries a nonce-based CSP and no unsafe-inline', async ({ request }) => {
    const resp = await request.get('/view');
    expect(resp.status()).toBe(200);
    const csp = resp.headers()['content-security-policy'] || '';
    expect(csp, 'viewer CSP should thread a script nonce').toMatch(/script-src\s+'nonce-[^']+'/);
    expect(csp, 'viewer CSP must never allow unsafe-inline scripts').not.toMatch(/script-src[^;]*unsafe-inline/);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("base-uri 'none'");
  });

  test('non-viewer responses fall back to script-src none', async ({ request }) => {
    const resp = await request.get('/this-path-does-not-exist-xyz');
    const csp = resp.headers()['content-security-policy'] || '';
    expect(csp, 'off-viewer responses must make any content inert').toContain("script-src 'none'");
  });

  test('static security headers are present on the viewer', async ({ request }) => {
    const h = (await request.get('/view')).headers();
    expect(h['x-frame-options']).toBe('DENY');
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(h['strict-transport-security']).toContain('max-age=');
    expect(h['permissions-policy']).toContain('geolocation=()');
  });
});
