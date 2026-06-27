import { test, expect } from '@playwright/test';

/**
 * The viewer renders attacker-controllable JSON (anyone can craft a report and
 * send a link). These tests load a deliberately malicious report through the
 * same render path as /r/{id} — the /view file-upload entry — and assert that
 * nothing it carries can execute. This regression-guards escHtml/escAttr and
 * the http-call title-attribute sink in particular.
 */

// A payload that tries to break out of BOTH a text context and a
// double-quoted attribute context, via three different sinks.
const XSS = '"><img src=x onerror="window.__xss_fired=true"><svg onload="window.__xss_fired=true"></svg>';
const poison = (base) => base + ' ' + XSS;

// A well-formed report whose every rendered string field carries the payload,
// so every escHtml/escAttr call site is exercised in one render.
const maliciousReport = {
  captured_at: '2026-01-01T00:00:00Z',
  summary: {
    duration_ns: 123456789, memory_peak: 12345678,
    query_count: 1, callback_count: 5, source_count: 2, http_call_count: 1,
  },
  request: {
    label: poison('Label'), method: poison('GET'), route_key: poison('route'),
    url: poison('/path'), role: poison('admin'), status: 200,
  },
  sources: [
    { source: poison('Plugin A'), name: poison('Plugin A'), type: poison('plugin'),
      exclusive_ms: 40, inclusive_ms: 50, call_count: 3, exclusive_ns: 40000000 },
    { source: poison('Theme'), name: poison('Theme'), type: poison('theme'),
      exclusive_ms: 10, inclusive_ms: 12, call_count: 1, exclusive_ns: 10000000 },
  ],
  queries: [
    { sql: poison('SELECT wp_posts'), source: poison('Plugin A'),
      caller: poison('do_thing()'), duration_ms: 5 },
  ],
  http_calls: [
    { method: poison('GET'), url: poison('https://evil.example/'), host: poison('evil.example'),
      caller: poison('wp_remote_get()'), source_name: poison('Plugin A'),
      duration_ms: 12, status: 200 },
  ],
  // Timeline data so the shared ScrutinizerTimeline renderer (which draws
  // attacker-controlled source/callback/host names) is exercised too.
  timeline: [
    { callback: poison('cb1'), tag: poison('init'), source: poison('Plugin A'), type: 'plugin',
      offset_ns: 0, wall_ns: 40000000, excl_ns: 40000000, pct_start: 0, pct_width: 0.4 },
    { callback: poison('cb2'), tag: poison('wp_head'), source: poison('Theme'), type: 'theme',
      offset_ns: 40000000, wall_ns: 10000000, excl_ns: 10000000, pct_start: 0.4, pct_width: 0.1 },
  ],
  phase_markers: [
    { name: poison('init'), offset_ns: 10000000 },
    { name: poison('wp_head'), offset_ns: 40000000 },
  ],
  memory_samples: [ { offset_ns: 0, bytes: 1000000 }, { offset_ns: 123456789, bytes: 12345678 } ],
  trace: [],
};

async function loadReport(page, report) {
  await page.goto('/view');
  await page.setInputFiles('#file-input', {
    name: 'report.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(report)),
  });
  // Wait for the report to render (request info is always shown, untabbed).
  await expect(page.locator('#app .route, .request-info, .metric-card').first())
    .toBeVisible({ timeout: 10000 });
  // Let any onerror/onload microtask fire.
  await page.waitForTimeout(400);
}

test.describe('viewer XSS hardening', () => {
  test('a malicious report executes nothing', async ({ page }) => {
    const dialogs = [];
    page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });

    await loadReport(page, maliciousReport);

    // 1. No injected onerror/onload/script ran.
    expect(await page.evaluate(() => window.__xss_fired === true),
      'an injected handler executed').toBe(false);
    // 2. No alert/confirm/prompt dialog was raised.
    expect(dialogs, 'a script raised a dialog').toEqual([]);
    // 3. No attacker markup became a live node.
    expect(await page.locator('img[onerror], svg[onload]').count(),
      'attacker markup parsed into live DOM nodes').toBe(0);
    // 4. Sanity: the payload survived as inert escaped text (render really ran).
    expect(await page.evaluate(() => document.body.innerText.includes('onerror=')),
      'payload should appear as inert text, proving the render path executed').toBe(true);
  });

  test('attribute-context payloads stay inside the attribute, not break out (escAttr)', async ({ page }) => {
    await loadReport(page, maliciousReport);

    // grp.sql renders into a data-sql attribute via escAttr — the same escAttr
    // path as the http-call title sink, and one that always renders from a
    // single query. If escAttr held, the whole payload is the attribute VALUE;
    // if it broke out, the value truncates at the first quote AND a live <img>
    // node appears. Both are checked, so this can't false-pass.
    const sqlNodes = page.locator('[data-sql]');
    expect(await sqlNodes.count(), 'the escAttr attribute sink must actually render')
      .toBeGreaterThan(0);

    const value = await sqlNodes.first().getAttribute('data-sql');
    expect(value, 'the payload must live inside the attribute value, not break out')
      .toContain('"><img');

    // Hard guarantee, timing-independent: no breakout became a live node.
    expect(await page.locator('img[onerror], svg[onload]').count(),
      'a broken-out attribute produced a live node').toBe(0);
    expect(await page.evaluate(() => window.__xss_fired === true)).toBe(false);
  });

  test('prototype-pollution keys in a report do not poison Object.prototype', async ({ page }) => {
    const polluting = {
      ...maliciousReport,
      // crafted keys that a naive keyed-map would copy onto the prototype
      sources: [{ __proto__: { polluted: true }, constructor: { polluted: true },
        source: 'X', name: 'X', type: 'plugin', exclusive_ms: 1, exclusive_ns: 1000000, call_count: 1 }],
    };
    await loadReport(page, polluting);
    expect(await page.evaluate(() => ({}).polluted === undefined),
      'Object.prototype was polluted by report keys').toBe(true);
    expect(await page.evaluate(() => window.__xss_fired === true)).toBe(false);
  });

  test('the shared timeline renderer produces the timeline in the viewer', async ({ page }) => {
    const errs = [];
    page.on('pageerror', (e) => errs.push(String(e)));
    // A clean report with timeline data → the module should render segments.
    const clean = {
      captured_at: '2026-01-01T00:00:00Z',
      summary: { duration_ns: 50000000, memory_peak: 12345678, source_count: 2 },
      request: { method: 'GET', route_key: '/', status: 200 },
      sources: [
        { source: 'plugin-a', name: 'Plugin A', type: 'plugin', exclusive_ns: 40000000, call_count: 3 },
        { source: 'twentytwentyfive', name: 'Theme', type: 'theme', exclusive_ns: 10000000, call_count: 1 },
      ],
      timeline: maliciousReport.timeline.map((t, i) => ({ ...t, source: i ? 'twentytwentyfive' : 'plugin-a', tag: 'init', callback: 'cb' })),
      phase_markers: [{ name: 'init', offset_ns: 10000000 }],
      memory_samples: [{ offset_ns: 0, bytes: 1000000 }, { offset_ns: 50000000, bytes: 12345678 }],
      queries: [], http_calls: [], trace: [],
    };
    await loadReport(page, clean);
    const segs = await page.$$eval('#panel-timeline [data-id]', (els) => els.length);
    expect(segs, 'timeline module rendered segments').toBeGreaterThan(0);
    expect(await page.evaluate(() => !!window.ScrutinizerTimeline)).toBe(true);
    expect(errs, 'no JS errors while rendering the timeline').toEqual([]);
  });
});
