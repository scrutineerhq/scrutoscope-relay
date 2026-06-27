/**
 * Scrutinizer Relay — Zero-Knowledge Encrypted Report Sharing
 * 
 * Cloudflare Worker serving:
 * - POST /r/           → store encrypted report
 * - GET  /r/{id}       → serve SPA viewer
 * - GET  /r/{id}/data  → return ciphertext for client-side decryption
 * - DELETE /r/{id}     → revoke a shared report
 * - GET  /view         → file upload viewer (drop zone for JSON exports)
 * - GET  /             → landing/redirect
 * 
 * R2 binding: REPORTS (scrutinizer-reports bucket) — report storage
 * DO binding: RATE_LIMITER — Durable Object rate limiting
 * 
 * Zero-knowledge: server stores only ciphertext + metadata.
 * Decryption key lives in URL fragment (#key), never sent to server.
 */

import {
  CORS_HEADERS,
  MAX_REPORT_SIZE,
  VALID_TTL_DAYS,
  DEFAULT_TTL_DAYS,
  generateNonce,
  withSecurityHeaders,
  timingSafeEqual,
  hashIP,
  shardKeyFromIP,
  jsonResponse,
} from './src/lib.js';

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // /.well-known/security.txt
      if (path === '/.well-known/security.txt') {
        return withSecurityHeaders(new Response(
          'Contact: mailto:hello@scrutineer.dev\n' +
          'Preferred-Languages: en\n' +
          'Canonical: https://scrutinizer.dev/.well-known/security.txt\n' +
          'Expires: 2027-06-26T00:00:00.000Z\n',
          { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } }
        ));
      }

      // Landing page
      if (path === '/' || path === '') {
        return withSecurityHeaders(handleLanding());
      }

      // GET /view — file upload viewer (drop zone for local JSON exports)
      if (path === '/view' && request.method === 'GET') {
        return withSecurityHeaders(handleFileViewer());
      }

      // POST /r/ — store encrypted report
      if (path === '/r/' && request.method === 'POST') {
        return withSecurityHeaders(await handleCreate(request, env));
      }
      // Also accept POST /r (no trailing slash)
      if (path === '/r' && request.method === 'POST') {
        return withSecurityHeaders(await handleCreate(request, env));
      }

      // GET /r/{id}/data — return ciphertext
      const dataMatch = path.match(/^\/r\/([a-f0-9]{32})\/data$/);
      if (dataMatch && request.method === 'GET') {
        return withSecurityHeaders(await handleGetData(dataMatch[1], request, env));
      }

      // POST /r/{id}/confirm-read — burn-after-read deletion, called by the
      // viewer only after it has successfully decrypted (D27).
      const confirmMatch = path.match(/^\/r\/([a-f0-9]{32})\/confirm-read$/);
      if (confirmMatch && request.method === 'POST') {
        return withSecurityHeaders(await handleConfirmRead(confirmMatch[1], env));
      }

      // DELETE /r/{id} — revoke report
      const deleteMatch = path.match(/^\/r\/([a-f0-9]{32})$/);
      if (deleteMatch && request.method === 'DELETE') {
        return withSecurityHeaders(await handleDelete(deleteMatch[1], request, env));
      }

      // GET /r/{id} — serve SPA viewer
      const viewMatch = path.match(/^\/r\/([a-f0-9]{32})$/);
      if (viewMatch && request.method === 'GET') {
        return withSecurityHeaders(await handleView(viewMatch[1], env));
      }

      return withSecurityHeaders(jsonResponse({ error: 'Not found' }, 404));
    } catch (err) {
      console.error('Worker error:', err);
      return withSecurityHeaders(jsonResponse({ error: 'Internal error' }, 500));
    }
  }
};

// ─── Durable Object Rate Limiter ────────────────────────────────────
//
// In-memory sliding-window counters sharded by IP prefix.
// Persisted to durable storage so counters survive DO eviction.
// Alarm-based GC cleans expired windows every 60 seconds.

const SK = 'w:';
const GC_INTERVAL_MS = 60_000;
const MAX_KEYS = 5_000;

export class RateLimiterDO {
  constructor(state) {
    this.state = state;
    this.windows = new Map();
    this.hydrated = false;
    this.state.storage.getAlarm().then((alarm) => {
      if (!alarm) {
        this.state.storage.setAlarm(Date.now() + GC_INTERVAL_MS);
      }
    });
  }

  async hydrate() {
    if (this.hydrated) return;
    const entries = await this.state.storage.list({ prefix: SK });
    for (const [storageKey, timestamps] of entries) {
      this.windows.set(storageKey.slice(SK.length), timestamps);
    }
    this.hydrated = true;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === '/check' && request.method === 'POST') {
      try {
        await this.hydrate();
        const body = await request.json();
        const result = this.checkLimit(body);
        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message || 'DO internal error' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Not found', { status: 404 });
  }

  async alarm() {
    await this.hydrate();
    this.gc();
    this.state.storage.setAlarm(Date.now() + GC_INTERVAL_MS);
  }

  checkLimit({ ip, endpoint, limit, windowSecs }) {
    const key = `${ip}:${endpoint}`;
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - windowSecs;

    let timestamps = this.windows.get(key);

    if (timestamps) {
      const idx = this.bisectRight(timestamps, cutoff);
      if (idx > 0) {
        timestamps = timestamps.slice(idx);
        if (timestamps.length === 0) {
          this.windows.delete(key);
          this.state.storage.delete(`${SK}${key}`);
        } else {
          this.windows.set(key, timestamps);
        }
      }
    }

    const count = timestamps?.length ?? 0;
    const oldest = timestamps?.[0] ?? now;
    const resetAt = oldest + windowSecs;

    if (count >= limit) {
      return { allowed: false, limit, remaining: 0, resetAt };
    }

    if (!timestamps) {
      this.windows.set(key, [now]);
    } else {
      timestamps.push(now);
    }
    const val = this.windows.get(key);
    if (val !== undefined) this.state.storage.put(`${SK}${key}`, val);
    this.maybeEvictColdKeys();

    const remaining = limit - count - 1;
    return { allowed: true, limit, remaining: Math.max(0, remaining), resetAt };
  }

  bisectRight(arr, value) {
    let lo = 0;
    let hi = arr.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (arr[mid] <= value) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  gc() {
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - 7200;
    const toDelete = [];
    const toUpdate = {};

    for (const [key, timestamps] of this.windows) {
      if (timestamps.length === 0 || timestamps[timestamps.length - 1] <= cutoff) {
        this.windows.delete(key);
        toDelete.push(`${SK}${key}`);
        continue;
      }
      const idx = this.bisectRight(timestamps, cutoff);
      if (idx > 0) {
        const trimmed = timestamps.slice(idx);
        if (trimmed.length === 0) {
          this.windows.delete(key);
          toDelete.push(`${SK}${key}`);
        } else {
          this.windows.set(key, trimmed);
          toUpdate[`${SK}${key}`] = trimmed;
        }
      }
    }

    if (toDelete.length > 0) {
      this.state.storage.delete(toDelete);
    }
    if (Object.keys(toUpdate).length > 0) {
      this.state.storage.put(toUpdate);
    }
  }

  maybeEvictColdKeys() {
    if (this.windows.size <= MAX_KEYS) return;
    const entries = Array.from(this.windows.entries());
    entries.sort((a, b) => {
      const aLast = a[1][a[1].length - 1] ?? 0;
      const bLast = b[1][b[1].length - 1] ?? 0;
      return aLast - bLast;
    });
    const toEvict = Math.ceil(entries.length * 0.1);
    const storageDeletes = [];
    for (let i = 0; i < toEvict; i++) {
      this.windows.delete(entries[i][0]);
      storageDeletes.push(`${SK}${entries[i][0]}`);
    }
    if (storageDeletes.length > 0) {
      this.state.storage.delete(storageDeletes);
    }
  }
}

/**
 * Landing page — Scrutineer branded, dark theme
 */
function handleLanding() {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scrutinizer Relay — Encrypted Report Sharing</title>
<meta name="robots" content="noindex, nofollow">
<meta property="og:title" content="Scrutinizer Relay">
<meta property="og:description" content="Zero-knowledge encrypted report sharing for WordPress performance diagnostics.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://scrutinizer.dev">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="Scrutinizer Relay">
<meta name="twitter:description" content="Zero-knowledge encrypted report sharing for WordPress performance diagnostics.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --teal: #15B7A4;
    --amber: #F0A94E;
    --bg: #0C2A28;
    --surface: #0F3330;
    --border: #1A4A45;
    --text: #E8F5F3;
    --muted: #7BA8A2;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 2rem;
    position: relative;
  }
  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
    background-size: 60px 60px;
    pointer-events: none;
  }
  .container { max-width: 480px; text-align: center; position: relative; z-index: 1; }
  .lock-icon {
    width: 64px; height: 64px;
    margin: 0 auto 1.5rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.75rem;
  }
  h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 0.375rem; letter-spacing: -0.02em; }
  .tagline {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem; color: var(--amber);
    letter-spacing: 0.02em; margin-bottom: 1.5rem;
  }
  p { font-size: 0.9375rem; line-height: 1.7; color: var(--muted); margin-bottom: 1rem; font-weight: 300; }
  a { color: var(--teal); text-decoration: none; }
  a:hover { color: var(--text); }
  .divider {
    width: 40px; height: 1px;
    background: var(--border);
    margin: 1.5rem auto;
  }
  .footer-link {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8125rem;
    color: var(--teal);
    padding: 0.625rem 1.25rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    transition: border-color 0.2s, color 0.2s;
    margin-top: 0.5rem;
  }
  .footer-link:hover { border-color: var(--teal); color: var(--text); }
</style>
</head>
<body>
<div class="container">
  <div class="lock-icon">🔒</div>
  <h1>Scrutinizer Relay</h1>
  <div class="tagline">Don't optimize. Scrutinize.</div>
  <p>Zero-knowledge encrypted report sharing. Reports are encrypted client-side before upload. This server stores only ciphertext it cannot read. Decryption keys never leave your browser.</p>
  <div class="divider"></div>
  <a href="https://scrutineer.dev/scrutinizer" class="footer-link">Get Scrutinizer for your WordPress site →</a>
</div>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'public, max-age=3600' }
  });
}

/**
 * POST /r/ — store encrypted report
 */
async function handleCreate(request, env) {
  // Rate limit — hash IP for GDPR-compliant storage.
  const rawIp = request.headers.get('cf-connecting-ip') || 'unknown';
  const ip = await hashIP(rawIp, env);
  const rateLimited = await checkRateLimit(env, ip, 'create', 10, 60);
  if (rateLimited) {
    return jsonResponse({ error: 'Rate limit exceeded. Try again later.' }, 429);
  }

  // Reject obviously-bad uploads before buffering the whole body.
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return jsonResponse({ error: 'Content-Type must be application/json' }, 415);
  }
  const declaredLen = parseInt(request.headers.get('content-length') || '0', 10);
  if (Number.isFinite(declaredLen) && declaredLen > MAX_REPORT_SIZE * 1.5) {
    return jsonResponse({ error: `Report too large. Maximum ${MAX_REPORT_SIZE / 1024 / 1024}MB.` }, 413);
  }

  // Parse body
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  // Validate required fields
  const { ciphertext, iv, ttl_days, has_passphrase, expire_after_reading, compressed, kdf_salt, kdf_iterations } = body;

  if (!ciphertext || typeof ciphertext !== 'string') {
    return jsonResponse({ error: 'Missing or invalid ciphertext' }, 400);
  }
  if (!iv || typeof iv !== 'string') {
    return jsonResponse({ error: 'Missing or invalid iv' }, 400);
  }

  // Size check (base64 ciphertext)
  if (ciphertext.length > MAX_REPORT_SIZE * 1.37) { // base64 overhead ~37%
    return jsonResponse({ error: `Report too large. Maximum ${MAX_REPORT_SIZE / 1024 / 1024}MB.` }, 413);
  }

  // TTL
  const ttl = VALID_TTL_DAYS.includes(ttl_days) ? ttl_days : DEFAULT_TTL_DAYS;
  const ttlSeconds = ttl * 24 * 60 * 60;
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  // Generate 128-bit capability ID
  const idBytes = new Uint8Array(16);
  crypto.getRandomValues(idBytes);
  const id = Array.from(idBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  // Generate revocation token
  const revokeBytes = new Uint8Array(32);
  crypto.getRandomValues(revokeBytes);
  const revokeToken = Array.from(revokeBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  // Store in R2 — single object with metadata
  const metadata = {
    iv,
    has_passphrase: !!has_passphrase,
    expire_after_reading: !!expire_after_reading,
    compressed: !!compressed,
    revoke_token: revokeToken,
    created_at: new Date().toISOString(),
    expires_at: expiresAt,
  };

  // Non-secret PBKDF2 parameters for passphrase shares (versioned format).
  // Stored so the viewer can reproduce the derivation; absent for legacy
  // shares, which the viewer handles with the old salt=IV / 100k fallback.
  if (has_passphrase && typeof kdf_salt === 'string' && Number.isFinite(kdf_iterations)) {
    metadata.kdf_salt = kdf_salt;
    metadata.kdf_iterations = String(kdf_iterations);
  }

  await env.REPORTS.put(`report:${id}`, ciphertext, {
    customMetadata: metadata,
  });

  return jsonResponse({
    id,
    expires_at: expiresAt,
    ttl_days: ttl,
    revoke_token: revokeToken,
    url: `https://scrutinizer.dev/r/${id}`,
  }, 201);
}

/**
 * GET /r/{id}/data — return ciphertext for client-side decryption
 */
async function handleGetData(id, request, env) {
  // Rate limit reads — hash IP for GDPR-compliant storage.
  const rawIp = request.headers.get('cf-connecting-ip') || 'unknown';
  const ip = await hashIP(rawIp, env);
  const rateLimited = await checkRateLimit(env, ip, 'read', 60, 60);
  if (rateLimited) {
    return jsonResponse({ error: 'Rate limit exceeded. Try again later.' }, 429);
  }

  // Fetch from R2
  const obj = await env.REPORTS.get(`report:${id}`);
  if (!obj) {
    return jsonResponse({ error: 'Report not found or expired.' }, 404);
  }

  const meta = obj.customMetadata;

  // Check expiry (R2 doesn't have native TTL)
  if (meta.expires_at && new Date(meta.expires_at) < new Date()) {
    await env.REPORTS.delete(`report:${id}`);
    return jsonResponse({ error: 'Report not found or expired.' }, 404);
  }

  // Read ciphertext
  const ciphertext = await obj.text();

  // Build response
  const response = {
    ciphertext,
    iv: meta.iv,
    has_passphrase: meta.has_passphrase === 'true' || meta.has_passphrase === true,
    compressed: meta.compressed === 'true' || meta.compressed === true,
    expire_after_reading: meta.expire_after_reading === 'true' || meta.expire_after_reading === true,
    created_at: meta.created_at,
    expires_at: meta.expires_at,
  };

  // Versioned PBKDF2 params for passphrase shares (absent on legacy shares).
  if (meta.kdf_salt) {
    response.kdf_salt = meta.kdf_salt;
    response.kdf_iterations = parseInt(meta.kdf_iterations, 10) || 600000;
  }

  // D27: do NOT delete on read. A GET only fetches the ciphertext; the viewer
  // calls POST /confirm-read after it has successfully decrypted. This means a
  // transient network/decrypt error no longer destroys the only copy, and an
  // unauthenticated GET can't silently burn someone else's report.

  return jsonResponse(response, 200, {
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
  });
}

/**
 * POST /r/{id}/confirm-read — delete a burn-after-read report after the viewer
 * confirms a successful decrypt. No-op (still 200) for reports that aren't
 * marked expire_after_reading, so the viewer can call it unconditionally.
 */
async function handleConfirmRead(id, env) {
  const obj = await env.REPORTS.head(`report:${id}`);
  if (!obj) {
    return jsonResponse({ success: true, deleted: false }, 200);
  }
  const meta = obj.customMetadata || {};
  if (meta.expire_after_reading === 'true' || meta.expire_after_reading === true) {
    await env.REPORTS.delete(`report:${id}`);
    return jsonResponse({ success: true, deleted: true }, 200);
  }
  return jsonResponse({ success: true, deleted: false }, 200);
}

/**
 * DELETE /r/{id} — revoke a shared report
 */
async function handleDelete(id, request, env) {
  const revokeToken = request.headers.get('X-Revoke-Token');
  if (!revokeToken) {
    return jsonResponse({ error: 'Missing X-Revoke-Token header' }, 401);
  }

  const obj = await env.REPORTS.head(`report:${id}`);
  if (!obj) {
    return jsonResponse({ error: 'Report not found or already expired.' }, 404);
  }

  const meta = obj.customMetadata;
  // Constant-time compare so a timing side-channel can't be used to recover
  // the revoke token character by character.
  if (!timingSafeEqual(meta.revoke_token || '', revokeToken)) {
    return jsonResponse({ error: 'Invalid revocation token.' }, 403);
  }

  // Revocation is immediate: deleting the R2 object removes the only copy.
  // No edge-cache purge is needed because every response that carries report
  // content (this endpoint's /data and the viewer HTML) is served with
  // Cache-Control: no-store, so nothing is ever held in a shared cache.
  await env.REPORTS.delete(`report:${id}`);

  return jsonResponse({ success: true, message: 'Report revoked.' }, 200);
}

/**
 * GET /r/{id} — serve the SPA viewer
 */
async function handleView(id, env) {
  // Check if report exists via R2 head (no data transfer)
  const obj = await env.REPORTS.head(`report:${id}`);
  let exists = !!obj;

  // Check expiry
  if (exists && obj.customMetadata.expires_at && new Date(obj.customMetadata.expires_at) < new Date()) {
    await env.REPORTS.delete(`report:${id}`);
    exists = false;
  }

  const nonce = generateNonce();
  const html = generateViewerHTML(id, exists, nonce);

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-CSP-Nonce': nonce,
      ...CORS_HEADERS,
    }
  });
}

/**
 * Rate limiting via Durable Object (sliding window).
 * Falls open on DO errors — relay stays available.
 *
 * IPs are HMAC-SHA256 hashed before storage for GDPR compliance.
 * The hash is consistent per secret, so rate limiting works, but
 * the raw IP is never persisted in DO storage.
 */
async function checkRateLimit(env, ip, endpoint, limit, windowSecs) {
  if (!env.RATE_LIMITER) return false; // no binding — fail open
  if (!ip) return false; // no pseudonymized IP (IP_HASH_SECRET unset) — fail open
  try {
    const shardKey = shardKeyFromIP(ip);
    const doId = env.RATE_LIMITER.idFromName(shardKey);
    const stub = env.RATE_LIMITER.get(doId);
    const resp = await stub.fetch(
      new Request('https://do/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, endpoint, limit, windowSecs }),
      }),
    );
    if (!resp.ok) return false; // DO error — fail open
    const result = await resp.json();
    return !result.allowed;
  } catch {
    return false; // fail open
  }
}

/**
 * Generate the full SPA viewer HTML
 */
function generateViewerHTML(reportId, reportExists, nonce) {
  return VIEWER_HTML.replace('{{REPORT_ID}}', reportId)
    .replace('{{REPORT_EXISTS}}', reportExists ? 'true' : 'false')
    .replace('{{MODE}}', 'relay')
    .replace('{{NONCE}}', nonce || '');
}

/**
 * GET /view — file upload viewer (drop zone for local JSON exports)
 */
function handleFileViewer() {
  const nonce = generateNonce();
  const html = VIEWER_HTML.replace('{{REPORT_ID}}', '')
    .replace('{{REPORT_EXISTS}}', 'false')
    .replace('{{MODE}}', 'file')
    .replace('{{NONCE}}', nonce);

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-CSP-Nonce': nonce,
      ...CORS_HEADERS,
    }
  });
}

// The SPA viewer HTML is defined below — inlined in the worker for single-file deploy
const VIEWER_HTML = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scrutinizer Report</title>
<meta name="robots" content="noindex, nofollow">
<meta property="og:title" content="Scrutinizer Relay">
<meta property="og:description" content="Zero-knowledge encrypted report sharing for WordPress performance diagnostics.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://scrutinizer.dev">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="Scrutinizer Relay">
<meta name="twitter:description" content="Zero-knowledge encrypted report sharing for WordPress performance diagnostics.">
<meta name="report-id" content="{{REPORT_ID}}">
<meta name="report-exists" content="{{REPORT_EXISTS}}">
<meta name="viewer-mode" content="{{MODE}}">
<style>
:root {
  --bg: #0a0a0a;
  --bg-card: #141414;
  --bg-card-hover: #1a1a1a;
  --border: #2a2a2a;
  --text: #e0e0e0;
  --text-muted: #888;
  --text-dim: #666;
  --accent: #60a5fa;
  --accent-hover: #93c5fd;
  --green: #4ade80;
  --red: #f87171;
  --amber: #fbbf24;
  --orange: #fb923c;
  --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;

  /* Source colors — match plugin */
  --src-plugin: #60a5fa;
  --src-theme: #c084fc;
  --src-core: #94a3b8;
  --src-mu-plugin: #fb923c;
  --src-drop-in: #4ade80;
  --src-unknown: #fbbf24;
  --src-unattributed: #475569;
}

html[data-theme="light"] {
  --bg: #f8f9fa;
  --bg-card: #ffffff;
  --bg-card-hover: #f1f3f5;
  --border: #dee2e6;
  --text: #1a1a1a;
  --text-muted: #6c757d;
  --text-dim: #adb5bd;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
}

/* Layout */
.viewer-header {
  border-bottom: 1px solid var(--border);
  padding: 1rem 1.5rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  background: var(--bg);
  z-index: 100;
}
.viewer-header h1 {
  font-size: 1rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.viewer-header .wordmark {
  font-family: var(--mono);
  font-weight: 700;
  letter-spacing: -0.02em;
  color: #15B7A4;
}
.viewer-header .controls {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}

/* Drop zone for file upload */
.drop-zone {
  border: 2px dashed var(--border);
  border-radius: 12px;
  padding: 4rem 2rem;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
  max-width: 480px;
  margin: 0 auto;
}
.drop-zone:hover,
.drop-zone.dragover {
  border-color: var(--accent);
  background: rgba(96, 165, 250, 0.05);
}
.drop-zone .icon {
  font-size: 3rem;
  margin-bottom: 1rem;
}
.drop-zone p {
  color: var(--text-muted);
  margin: 0.5rem 0;
}
.drop-zone .hint {
  font-size: 0.8rem;
  color: var(--text-dim);
}
.drop-zone input[type="file"] {
  display: none;
}
.theme-toggle {
  background: none;
  border: 1px solid var(--border);
  color: var(--text-muted);
  padding: 0.35rem 0.6rem;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.85rem;
}
.theme-toggle:hover { border-color: var(--text-muted); }

.container {
  max-width: 960px;
  margin: 0 auto;
  padding: 0 1.5rem;
}

/* Guidance banner */
.guidance {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.5rem;
  position: relative;
}
.guidance h2 { font-size: 1rem; margin-bottom: 0.5rem; }
.guidance p { font-size: 0.9rem; color: var(--text-muted); margin-bottom: 0.4rem; }
.guidance .dismiss {
  position: absolute;
  top: 0.75rem;
  right: 1rem;
  background: none;
  border: none;
  color: var(--text-dim);
  cursor: pointer;
  font-size: 1.1rem;
}
.guidance ul { list-style: none; margin-top: 0.5rem; }
.guidance li { font-size: 0.9rem; color: var(--text-muted); padding: 0.15rem 0; }
.guidance li strong { color: var(--text); }

/* States */
.state-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 60vh;
  text-align: center;
  gap: 1rem;
}
.state-container .icon { font-size: 3rem; }
.state-container h2 { font-size: 1.25rem; font-weight: 600; }
.state-container p { font-size: 0.95rem; color: var(--text-muted); max-width: 400px; }

/* Passphrase input */
.passphrase-form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  align-items: center;
  margin-top: 0.5rem;
}
.passphrase-form input {
  font-family: var(--mono);
  font-size: 1rem;
  padding: 0.6rem 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  width: 280px;
  text-align: center;
}
.passphrase-form input:focus { outline: none; border-color: var(--accent); }
.passphrase-form button, .btn {
  font-family: var(--sans);
  font-size: 0.9rem;
  padding: 0.5rem 1.25rem;
  background: var(--accent);
  color: #000;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
}
.passphrase-form button:hover, .btn:hover { background: var(--accent-hover); }
.error-text { color: var(--red); font-size: 0.85rem; }

/* Loading spinner */
.spinner {
  width: 32px; height: 32px;
  border: 3px solid var(--border);
  border-top: 3px solid var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* Metric cards */
.metrics {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.metric-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
}
.metric-card .label {
  font-size: 0.8rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.25rem;
}
.metric-card .value {
  font-size: 1.5rem;
  font-weight: 600;
  font-family: var(--mono);
}
.metric-card .sub {
  font-size: 0.8rem;
  color: var(--text-dim);
  margin-top: 0.15rem;
}

/* Request info */
.request-info {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  margin-bottom: 1.5rem;
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  align-items: center;
}
.request-info .route {
  font-family: var(--mono);
  font-size: 1.1rem;
  font-weight: 600;
}
.request-info .route-label {
  font-size: 0.85rem;
  color: var(--text-muted);
}
.request-info .meta-item {
  font-size: 0.85rem;
  color: var(--text-muted);
}
.request-info .meta-item strong { color: var(--text); }

/* Tab bar */
.tab-bar {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1.5rem;
  overflow-x: auto;
}
.tab-bar button {
  font-family: var(--sans);
  font-size: 0.85rem;
  padding: 0.6rem 1.25rem;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-muted);
  cursor: pointer;
  white-space: nowrap;
}
.tab-bar button:hover { color: var(--text); }
.tab-bar button.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
}
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* Breakdown bar */
.breakdown-bar {
  display: flex;
  height: 32px;
  border-radius: 6px;
  overflow: hidden;
  margin-bottom: 1rem;
  border: 1px solid var(--border);
}
.breakdown-segment {
  min-width: 2px;
  position: relative;
  transition: opacity 0.15s;
}
.breakdown-segment:hover { opacity: 0.85; }
.breakdown-segment .tooltip {
  display: none;
  position: absolute;
  bottom: 100%;
  left: 50%;
  transform: translateX(-50%);
  background: #000;
  color: #fff;
  padding: 0.3rem 0.6rem;
  border-radius: 4px;
  font-size: 0.75rem;
  white-space: nowrap;
  z-index: 10;
  margin-bottom: 4px;
}
.breakdown-segment:hover .tooltip { display: block; }

/* Tables */
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
.data-table th {
  text-align: left;
  padding: 0.6rem 0.75rem;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  font-weight: 500;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.data-table td {
  padding: 0.6rem 0.75rem;
  border-bottom: 1px solid var(--border);
}
.data-table tr:hover td { background: var(--bg-card-hover); }
.data-table .mono { font-family: var(--mono); font-size: 0.8rem; }
.data-table .num { text-align: right; font-family: var(--mono); }
.data-table .source-badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}
.data-table .weight-bar {
  height: 4px;
  border-radius: 2px;
  margin-top: 0.25rem;
  min-width: 2px;
}
.data-table .slow { color: var(--red); }
.data-table .warn { color: var(--amber); }
.data-table tr.slow-row td { background: rgba(239,68,68,0.06); }

/* Query enhancements */
.queries-header { margin-bottom: 1rem; }
.queries-summary { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.5rem; }
.queries-summary strong { color: var(--text-primary); }
.duplicate-flag { color: var(--red); font-weight: 600; }

.queries-sources { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.75rem; }
.query-source-pill {
  display: inline-block; padding: 0.2rem 0.6rem; border: none; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; color: #fff; cursor: pointer;
  transition: opacity 0.15s; font-family: var(--sans);
}
.query-source-pill:hover { opacity: 0.8; }

.queries-toggle { display: inline-flex; border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
.toggle-btn {
  padding: 0.3rem 0.8rem; border: none; background: var(--bg-card);
  font-size: 0.75rem; color: var(--text-muted); cursor: pointer; font-family: var(--sans);
}
.toggle-btn + .toggle-btn { border-left: 1px solid var(--border); }
.toggle-btn.active { background: var(--teal); color: #fff; }

.query-filter-bar {
  padding: 0.5rem 0.75rem; margin-bottom: 0.75rem; font-size: 0.8rem;
  background: var(--bg-card); border: 1px solid var(--teal); border-radius: 4px;
}
.clear-filter { border: none; background: none; color: var(--red); cursor: pointer; font-size: 0.75rem; margin-left: 0.5rem; }

.duplicate-badge {
  display: inline-block; padding: 0.15rem 0.5rem; background: var(--red); color: #fff;
  border-radius: 10px; font-size: 0.75rem; font-weight: 700;
}

.group-row { cursor: pointer; }
.group-row:hover td { background: var(--bg-card-hover); }
.group-detail { background: var(--bg-body); }
.group-detail-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin: 0.5rem 0; }
.group-detail-table th, .group-detail-table td { padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--border); text-align: left; }
.group-detail-table th { font-size: 0.75rem; color: var(--text-muted); }

.sql-expandable { cursor: pointer; }
.sql-expandable:hover { color: var(--teal); }
.sql-full { white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; cursor: pointer; }

/* Timeline */
.timeline-container {
  position: relative;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  overflow: visible;
}
.timeline-zoom-controls {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 12px;
  font-size: 0.8rem;
}
.timeline-zoom-controls button {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 4px;
  width: 28px;
  height: 28px;
  font-size: 1rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
}
.timeline-zoom-controls button:hover {
  background: var(--border);
}
.timeline-zoom-level {
  font-family: var(--mono);
  color: var(--text-muted);
  min-width: 28px;
  text-align: center;
}
.timeline-zoom-hint {
  color: var(--text-dim);
  font-size: 0.7rem;
  margin-left: 8px;
}
.timeline-viewport {
  overflow-x: auto;
  overflow-y: visible;
  position: relative;
}
.rubber-band {
  position: absolute;
  top: 0;
  bottom: 0;
  background: rgba(21, 183, 164, 0.15);
  border-left: 2px solid var(--teal);
  border-right: 2px solid var(--teal);
  pointer-events: none;
  z-index: 5;
  display: none;
}
.timeline-zoom-wrapper {
  min-width: 100%;
  position: relative;
  transform-origin: left top;
}
.timeline-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  margin-top: 12px;
  font-size: 0.75rem;
  color: var(--text-muted);
}
.timeline-legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}
.timeline-legend-swatch {
  width: 10px;
  height: 10px;
  border-radius: 2px;
  flex-shrink: 0;
}
.milestones {
  position: relative;
  width: 100%;
}
.milestone {
  position: absolute;
  bottom: 0;
  transform: translateX(-50%);
}
.milestone.milestone-right .milestone-label {
  left: auto;
  right: 50%;
  transform: none;
  text-align: right;
}
.milestone.milestone-left .milestone-label {
  left: 50%;
  transform: none;
  text-align: left;
}
.milestone-stem {
  display: block;
  width: 1px;
  height: 100%;
  background: var(--border);
  position: absolute;
  bottom: 0;
  left: 50%;
}
.milestone-dot {
  display: block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--text-muted);
  position: absolute;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
}
.milestone-label {
  display: block;
  font-size: 0.65rem;
  color: var(--text-muted);
  white-space: nowrap;
  text-align: center;
  position: absolute;
  top: 0;
  left: 50%;
  transform: translateX(-50%);
  font-family: var(--mono);
}
.timeline-bar {
  position: relative;
  height: 32px;
  background: var(--bg);
  border-radius: 4px;
  overflow: hidden;
}
.timeline-bar .segment {
  position: absolute;
  top: 0;
  height: 100%;
  min-width: 1px;
  cursor: default;
}
.timeline-bar .segment:hover {
  opacity: 0.8;
}
.timeline-axis {
  position: relative;
  height: 18px;
  margin-top: 4px;
  font-size: 0.7rem;
  color: var(--text-dim);
  font-family: var(--mono);
}
.timeline-axis .tick {
  position: absolute;
  transform: translateX(-50%);
  white-space: nowrap;
}
.timeline-axis .tick:first-child {
  transform: none;
}
.timeline-axis .tick:last-child {
  transform: translateX(-100%);
}

/* HTTP lollipops below bar */
.http-lollipops {
  position: relative;
  width: 100%;
  margin-top: 2px;
}
.http-lollipop {
  position: absolute;
  top: 0;
  transform: translateX(-50%);
}
.http-stem {
  display: block;
  width: 1px;
  height: calc(100% - 24px);
  background: var(--border);
  position: absolute;
  top: 0;
  left: 50%;
}
.http-dot {
  display: block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  position: absolute;
  bottom: 16px;
  left: 50%;
  transform: translateX(-50%);
}
.http-dot.http-fast { background: #27ae60; }
.http-dot.http-medium { background: #e67e22; }
.http-dot.http-slow { background: #e74c3c; }
.http-label {
  display: block;
  font-size: 0.6rem;
  color: var(--text-dim);
  white-space: nowrap;
  position: absolute;
  bottom: 0;
  left: 50%;
  transform: translateX(-50%);
}
.http-label em {
  font-style: normal;
  color: var(--text-muted);
}
.http-lollipop.http-error .http-stem { background: #e74c3c; }

/* Query density */
.query-density-wrap {
  display: flex;
  align-items: flex-end;
  gap: 6px;
  margin-top: 6px;
}
.density-label {
  font-size: 0.65rem;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  flex-shrink: 0;
  padding-bottom: 1px;
  font-family: var(--mono);
}
.query-density {
  display: flex;
  align-items: flex-end;
  height: 16px;
  flex: 1;
  gap: 1px;
  border-radius: 2px;
  overflow: hidden;
}
.density-bar {
  flex: 1;
  min-height: 0;
  border-radius: 1px;
}
.density-bar.density-none { background: transparent; }
.density-bar.density-normal { background: #c3c4c7; }
.density-bar.density-medium { background: #dba617; }
.density-bar.density-slow { background: #d63638; }

/* Memory sparkline */
/* Memory sparkline — overlaid on the timeline bar */
.memory-overlay-svg {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 2;
}
.memory-overlay-svg .memory-hit-area,
.memory-overlay-svg .memory-line {
  pointer-events: stroke;
  cursor: help;
}
.memory-overlay-svg:hover .memory-line {
  stroke: rgba(230, 126, 34, 1);
  stroke-width: 2.5;
}
.memory-overlay-label {
  position: absolute;
  right: 4px;
  top: 2px;
  font-size: 0.6rem;
  color: #e67e22;
  font-family: var(--mono);
  white-space: nowrap;
  pointer-events: none;
  z-index: 3;
  text-shadow: 0 0 3px rgba(0,0,0,0.6), 0 0 6px rgba(0,0,0,0.4);
}

/* Legend */
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  margin-top: 1rem;
  font-size: 0.8rem;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  color: var(--text-muted);
}
.legend-swatch {
  width: 12px;
  height: 12px;
  border-radius: 3px;
  flex-shrink: 0;
}

/* Source pill for assets */
.asset-source-pill {
  display: inline-block;
  font-size: 0.7rem;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  margin-right: 0.35rem;
  color: #fff;
  font-weight: 500;
}

/* Diagnostics */
.diagnostics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
}
.diag-section {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
}
.diag-section h3 {
  font-size: 0.85rem;
  font-weight: 600;
  margin-bottom: 0.75rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.diag-row {
  display: flex;
  justify-content: space-between;
  padding: 0.3rem 0;
  font-size: 0.85rem;
}
.diag-row .diag-key { color: var(--text-muted); }
.diag-row .diag-val { font-family: var(--mono); font-size: 0.8rem; }

/* Trace tree */
.trace-tree { font-size: 0.85rem; }
.trace-phase {
  margin-bottom: 0.5rem;
}
.trace-phase > summary {
  cursor: pointer;
  padding: 0.5rem 0.75rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-weight: 500;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.trace-phase > summary::before {
  content: '▸';
  font-size: 0.7rem;
  transition: transform 0.15s;
}
.trace-phase[open] > summary::before { content: '▾'; }
.trace-phase > summary .phase-time {
  margin-left: auto;
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--text-muted);
}
.trace-callbacks {
  padding: 0.25rem 0 0.25rem 1.5rem;
}
.trace-callback {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.25rem 0.5rem;
  font-size: 0.8rem;
  border-bottom: 1px solid var(--border);
}
.trace-callback:last-child { border-bottom: none; }
.trace-callback .cb-name {
  font-family: var(--mono);
  font-size: 0.78rem;
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.trace-callback .cb-time {
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--text-muted);
  white-space: nowrap;
}
.trace-callback .cb-source {
  font-size: 0.7rem;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  white-space: nowrap;
}

/* Security footer */
.security-footer {
  margin-top: 3rem;
  padding: 1rem 0;
  border-top: 1px solid var(--border);
  text-align: center;
  font-size: 0.8rem;
  color: var(--text-dim);
}
.security-footer a { color: var(--accent); text-decoration: none; }

/* Print */
@media print {
  .viewer-header, .theme-toggle, .guidance .dismiss { display: none; }
  body { background: #fff; color: #000; }
  .tab-panel { display: block !important; page-break-inside: avoid; margin-bottom: 2rem; }
  .tab-bar { display: none; }
}

/* Responsive */
@media (max-width: 640px) {
  .metrics { grid-template-columns: 1fr 1fr; }
  .request-info { flex-direction: column; gap: 0.5rem; }
  .container { padding: 1rem; }
}
</style>
</head>
<body>

<header class="viewer-header">
  <h1><a href="https://scrutineer.dev/scrutinizer" style="color:inherit;text-decoration:none"><span class="wordmark">Scrutinizer</span></a> Report</h1>
  <div class="controls">
    <button class="theme-toggle" id="theme-toggle" title="Toggle theme">◐</button>
  </div>
</header>

<div class="container">
  <div id="app"></div>
</div>

<script nonce="{{NONCE}}">
(function() {
  'use strict';

  const REPORT_ID = document.querySelector('meta[name="report-id"]').content;
  const REPORT_EXISTS = document.querySelector('meta[name="report-exists"]').content === 'true';
  const VIEWER_MODE = document.querySelector('meta[name="viewer-mode"]').content;
  const app = document.getElementById('app');

  const SOURCE_COLORS = {
    plugin: '#60a5fa',
    theme: '#c084fc',
    core: '#94a3b8',
    'mu-plugin': '#fb923c',
    'drop-in': '#4ade80',
    unknown: '#fbbf24',
    unattributed: '#475569',
  };

  // Per-source color palette — gives each plugin/theme a unique color.
  var pluginPalette = [
    '#2271b1', '#e67e22', '#9b59b6', '#27ae60', '#e74c3c',
    '#3498db', '#f39c12', '#1abc9c', '#e91e63', '#00bcd4',
    '#8bc34a', '#ff5722', '#607d8b', '#795548', '#9c27b0'
  ];
  var pluginColorMap = {};
  var colorIndex = 0;

  function getSourceColor(slug, type) {
    if (type === 'unattributed') return SOURCE_COLORS.unattributed || '#475569';
    if (type === 'unknown' || slug === 'unknown') return SOURCE_COLORS.unknown;
    var key = type + ':' + slug;
    if (!pluginColorMap[key]) {
      pluginColorMap[key] = pluginPalette[colorIndex % pluginPalette.length];
      colorIndex++;
    }
    return pluginColorMap[key];
  }

  function truncateHost(str, max) {
    if (!str || str.length <= max) return str || '';
    return str.substring(0, max - 1) + '\u2026';
  }

  // Theme
  function toggleTheme() {
    const html = document.documentElement;
    const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
    html.dataset.theme = next;
    localStorage.setItem('scrutinizer-theme', next);
  }
  const themeToggleBtn = document.getElementById('theme-toggle');
  if (themeToggleBtn) themeToggleBtn.addEventListener('click', toggleTheme);
  const savedTheme = localStorage.getItem('scrutinizer-theme');
  if (savedTheme) document.documentElement.dataset.theme = savedTheme;

  // Entry point
  async function init() {
    // File upload mode — show drop zone
    if (VIEWER_MODE === 'file') {
      showFileUpload();
      return;
    }

    // Relay mode — need fragment key
    const fragment = window.location.hash.slice(1);
    if (!fragment) {
      showError('🔗', 'Incomplete link',
        'This report link is incomplete. Make sure the full URL was copied, including everything after the # symbol.');
      return;
    }

    // Report doesn't exist?
    if (!REPORT_EXISTS) {
      showError('⏱️', 'Report expired or revoked',
        'This report has expired or been revoked by the owner.');
      return;
    }

    // Show loading
    showLoading('Fetching encrypted report…');

    try {
      // Fetch ciphertext
      const resp = await fetch('/r/' + REPORT_ID + '/data');
      if (!resp.ok) {
        if (resp.status === 404) {
          showError('⏱️', 'Report expired or revoked',
            'This report has expired or been revoked by the owner.');
        } else if (resp.status === 429) {
          showError('🚦', 'Too many requests',
            'Please wait a moment and try again.');
        } else {
          showError('❌', 'Failed to load report',
            'Something went wrong fetching this report.');
        }
        return;
      }

      const data = await resp.json();

      // Passphrase protected?
      if (data.has_passphrase) {
        showPassphrasePrompt(data, fragment);
        return;
      }

      // Decrypt (and decompress if needed)
      showLoading('Decrypting report…');
      const report = await decryptReport(data.ciphertext, data.iv, fragment, null, data.compressed);
      renderReport(report, data);
      confirmReadIfNeeded(data);

    } catch (err) {
      console.error('Init error:', err);
      showError('🔓', 'Decryption failed',
        'This report could not be decrypted. The link may be damaged or the key is incorrect.');
    }
  }

  // File upload drop zone
  function showFileUpload() {
    var html = '<div class="drop-zone" id="drop-zone">';
    html += '<div class="icon">📂</div>';
    html += '<p>Drop a Scrutinizer JSON export or click to browse</p>';
    html += '<p class="hint">Exported via WP-CLI or the plugin dashboard. No data leaves your browser.</p>';
    html += '<input type="file" id="file-input" accept=".json,application/json">';
    html += '</div>';
    app.innerHTML = html;

    var zone = document.getElementById('drop-zone');
    var input = document.getElementById('file-input');

    zone.addEventListener('click', function() { input.click(); });

    zone.addEventListener('dragover', function(e) {
      e.preventDefault();
      zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', function() {
      zone.classList.remove('dragover');
    });
    zone.addEventListener('drop', function(e) {
      e.preventDefault();
      zone.classList.remove('dragover');
      if (e.dataTransfer.files.length) loadFile(e.dataTransfer.files[0]);
    });
    input.addEventListener('change', function() {
      if (input.files.length) loadFile(input.files[0]);
    });
  }

  function loadFile(file) {
    if (!file.name.endsWith('.json') && file.type !== 'application/json') {
      showError('⚠️', 'Unsupported file', 'Please select a JSON file exported from Scrutinizer.');
      return;
    }

    showLoading('Reading file…');

    var reader = new FileReader();
    reader.onload = function(e) {
      try {
        var report = JSON.parse(e.target.result);
        // Validate it looks like a Scrutinizer export
        if (!report.summary && !report.profile_data) {
          showError('⚠️', 'Invalid format', 'This file does not appear to be a Scrutinizer export.');
          return;
        }
        // If it has profile_data wrapper, unwrap it
        var data = report.profile_data ? report.profile_data : report;
        renderReport(data, { created_at: report._scrutinizer ? report._scrutinizer.exported_at : null });
      } catch (err) {
        console.error('Parse error:', err);
        showError('⚠️', 'Parse error', 'Could not parse this file. Make sure it is valid JSON.');
      }
    };
    reader.onerror = function() {
      showError('❌', 'Read error', 'Could not read this file.');
    };
    reader.readAsText(file);
  }

  // Decrypt
  async function decryptReport(ciphertextB64, ivB64, keyB64, passphrase, compressed, kdf) {
    let keyBytes = base64urlDecode(keyB64);

    // If passphrase, unwrap the data key first
    if (passphrase) {
      // The keyB64 in fragment is the wrapped key when passphrase is used
      // We need to derive the wrapping key from passphrase and unwrap
      const enc = new TextEncoder();
      const passphraseKey = await crypto.subtle.importKey(
        'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits', 'deriveKey']
      );
      // Versioned format provides a dedicated salt + iteration count. Legacy
      // shares predate that and reused the content IV as salt at 100k.
      const salt = (kdf && kdf.salt) ? base64urlDecode(kdf.salt) : base64urlDecode(ivB64);
      const iterations = (kdf && kdf.iterations) ? kdf.iterations : 100000;
      const wrappingKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        passphraseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      // Fragment contains the encrypted data key
      const wrappedKeyIv = keyBytes.slice(0, 12);
      const wrappedKeyData = keyBytes.slice(12);
      const unwrappedKey = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: wrappedKeyIv },
        wrappingKey,
        wrappedKeyData
      );
      keyBytes = new Uint8Array(unwrappedKey);
    }

    const key = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );

    const iv = base64urlDecode(ivB64);
    const ciphertext = base64urlDecode(ciphertextB64);

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );

    // Decompress if the payload was gzipped before encryption
    let jsonBytes;
    if (compressed) {
      const ds = new DecompressionStream('gzip');
      const writer = ds.writable.getWriter();
      writer.write(new Uint8Array(plaintext));
      writer.close();
      const reader = ds.readable.getReader();
      const chunks = [];
      // Cap the decompressed size. A ~10MB ciphertext can gzip-expand to GBs;
      // without a bound a crafted report would OOM the viewer tab.
      const MAX_DECOMPRESSED = 64 * 1024 * 1024;
      let decompressedBytes = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        decompressedBytes += value.length;
        if (decompressedBytes > MAX_DECOMPRESSED) {
          reader.cancel();
          throw new Error('Report is too large to display.');
        }
        chunks.push(value);
      }
      const totalLen = chunks.reduce(function(a, c) { return a + c.length; }, 0);
      jsonBytes = new Uint8Array(totalLen);
      let offset = 0;
      for (let i = 0; i < chunks.length; i++) {
        jsonBytes.set(chunks[i], offset);
        offset += chunks[i].length;
      }
    } else {
      jsonBytes = new Uint8Array(plaintext);
    }

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(jsonBytes));
  }

  // Base64url decode
  function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  // UI States
  function showLoading(msg) {
    app.innerHTML = '<div class="state-container"><div class="spinner"></div><p>' + escHtml(msg) + '</p></div>';
  }

  function showError(icon, title, msg) {
    app.innerHTML = '<div class="state-container"><div class="icon">' + icon + '</div>' +
      '<h2>' + escHtml(title) + '</h2><p>' + escHtml(msg) + '</p></div>';
  }

  function showPassphrasePrompt(data, fragment) {
    app.innerHTML = '<div class="state-container"><div class="icon">🔐</div>' +
      '<h2>Passphrase required</h2>' +
      '<p>This report is protected with a passphrase.</p>' +
      '<div class="passphrase-form">' +
      '<input type="password" id="passphrase-input" placeholder="Enter passphrase" autofocus>' +
      '<button id="passphrase-decrypt">Decrypt</button>' +
      '<div id="passphrase-error" class="error-text"></div>' +
      '</div></div>';

    const input = document.getElementById('passphrase-input');
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') window._attemptDecrypt(); });
    document.getElementById('passphrase-decrypt').addEventListener('click', () => window._attemptDecrypt());

    let attempts = 0;
    window._attemptDecrypt = async function() {
      const passphrase = input.value;
      if (!passphrase) return;

      attempts++;
      if (attempts > 5) {
        document.getElementById('passphrase-error').textContent = 'Too many attempts.';
        return;
      }

      try {
        showLoading('Decrypting…');
        const report = await decryptReport(data.ciphertext, data.iv, fragment, passphrase, data.compressed, { salt: data.kdf_salt, iterations: data.kdf_iterations });
        renderReport(report, data);
        confirmReadIfNeeded(data);
      } catch {
        showPassphrasePrompt(data, fragment);
        document.getElementById('passphrase-error').textContent = 'Incorrect passphrase. Please try again.';
      }
    };
  }

  // Render the full report
  // D27: tell the relay to delete a burn-after-read report, but only after a
  // successful decrypt+render. Fire-and-forget and best-effort — the report is
  // already shown, and the relay no-ops for non-burn reports.
  function confirmReadIfNeeded(meta) {
    if (VIEWER_MODE !== 'relay' || !meta || !meta.expire_after_reading) {
      return;
    }
    fetch('/r/' + REPORT_ID + '/confirm-read', { method: 'POST' }).catch(() => {});
  }

  function renderReport(report, meta) {
    // Reset per-source color assignments for this report.
    pluginColorMap = {};
    colorIndex = 0;

    const guidanceDismissed = localStorage.getItem('scrutinizer-guidance-dismissed');

    let html = '';

    // Guidance banner
    if (!guidanceDismissed) {
      html += '<div class="guidance" id="guidance">' +
        '<button class="dismiss" id="dismiss-guidance">✕</button>' +
        '<h2>📊 How to read this report</h2>' +
        '<p>This performance report was shared with you by a WordPress site owner. It shows server-side profiling data — where time goes during a page request.</p>' +
        '<ul>' +
        '<li><strong>Timeline</strong> — when things happen during request processing</li>' +
        '<li><strong>Breakdown</strong> — which plugins and theme use the most server time</li>' +
        '<li><strong>Sources</strong> — detailed attribution with callback counts</li>' +
        '<li><strong>Queries</strong> — database calls, sorted by duration</li>' +
        '</ul>' +
        '<p style="margin-top:0.75rem;">\ud83d\udd12 Do not share this link with anyone else \u2014 it contains the key to view this report.</p>' +
        '</div>';
    }

    // Extract data
    const summary = report.summary || {};
    const request = report.request || {};
    const sources = report.sources || [];
    const queries = report.queries || [];
    const timeline = report.timeline || [];
    const milestones = report.phase_markers || [];
    const diagnostics = report.diagnostics || null;
    const trace = report.trace || [];
    const httpCalls = report.http_calls || [];
    const autoloadedOptions = report.autoloaded_options || null;
    const enqueuedAssets = report.enqueued_assets || null;

    const durationMs = (summary.duration_ns || 0) / 1e6;
    const memoryMb = (summary.memory_peak || 0) / (1024 * 1024);
    const queryCount = summary.query_count || 0;
    const callbackCount = summary.callback_count || 0;

    // Request info
    html += '<div class="request-info">';
    if (request.label) {
      html += '<div><div class="route-label">' + escHtml(request.label) + '</div>' +
        '<div class="route">' + escHtml(request.method || 'GET') + ' ' + escHtml(request.route_key || request.url || '/') + '</div></div>';
    } else {
      html += '<div class="route">' + escHtml(request.method || 'GET') + ' ' + escHtml(request.route_key || request.url || '/') + '</div>';
    }
    if (request.role) html += '<div class="meta-item"><strong>Role:</strong> ' + escHtml(request.role) + '</div>';
    if (request.status) html += '<div class="meta-item"><strong>Status:</strong> ' + escHtml(String(request.status)) + '</div>';
    if (report.captured_at) html += '<div class="meta-item"><strong>Captured:</strong> ' + escHtml(formatDate(report.captured_at)) + '</div>';
    html += '<div class="meta-item" style="color:var(--text-dim)">Expires: ' + escHtml(formatDate(meta.expires_at)) + '</div>';
    html += '</div>';

    // Metric cards
    html += '<div class="metrics">';
    html += metricCard('Server Request Duration', formatMs(durationMs), '');
    html += metricCard('Peak Memory', memoryMb.toFixed(1) + ' MB', '');
    html += metricCard('DB Queries', queryCount.toString(), queries.length ? formatMs(queries.reduce((s, q) => s + (q.time_ms || 0), 0)) + ' total' : '');
    html += metricCard('Callbacks', callbackCount.toString(), sources.length + ' sources');
    if (httpCalls.length) {
      const httpTotalMs = httpCalls.reduce((s, h) => s + (h.duration_ms || 0), 0);
      html += metricCard('HTTP Calls', httpCalls.length.toString(), formatMs(httpTotalMs) + ' total');
    }
    html += '</div>';

    // Tab bar
    const tabs = [];
    if (timeline.length || milestones.length) tabs.push({ id: 'timeline', label: 'Timeline' });
    if (sources.length) tabs.push({ id: 'breakdown', label: 'Breakdown' });
    if (sources.length) tabs.push({ id: 'sources', label: 'Sources' });
    if (queries.length) tabs.push({ id: 'queries', label: 'Queries' });
    if (trace.length) tabs.push({ id: 'trace', label: 'Trace' });
    if (httpCalls.length) tabs.push({ id: 'http_calls', label: 'HTTP Calls' });
    if (autoloadedOptions && autoloadedOptions.total_size) tabs.push({ id: 'options', label: 'Options' });
    if (enqueuedAssets && ((enqueuedAssets.scripts || []).length || (enqueuedAssets.styles || []).length)) tabs.push({ id: 'assets', label: 'Assets' });
    if (diagnostics) tabs.push({ id: 'diagnostics', label: 'Diagnostics' });

    html += '<div class="tab-bar">';
    tabs.forEach((t, i) => {
      html += '<button data-tab="' + t.id + '" class="' + (i === 0 ? 'active' : '') + '">' + t.label + '</button>';
    });
    html += '</div>';

    // Tab panels
    // Timeline
    if (timeline.length || milestones.length) {
      html += '<div class="tab-panel' + (tabs[0]?.id === 'timeline' ? ' active' : '') + '" id="panel-timeline">';
      html += renderTimeline(timeline, milestones, durationMs, httpCalls, queries, sources);
      html += '</div>';
    }

    // Breakdown
    if (sources.length) {
      html += '<div class="tab-panel' + (tabs[0]?.id === 'breakdown' ? ' active' : '') + '" id="panel-breakdown">';
      html += '<p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:1rem;">Where server request duration is spent, broken down by source.</p>';
      html += renderBreakdownBar(sources, durationMs);
      html += renderLegend(sources);
      html += '</div>';
    }

    // Sources table
    if (sources.length) {
      html += '<div class="tab-panel" id="panel-sources">';
      html += '<p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:1rem;">Each source&#39;s contribution to server request duration, with callback counts.</p>';
      html += renderSourcesTable(sources, durationMs);
      html += '</div>';
    }

    // Queries table
    if (queries.length) {
      html += '<div class="tab-panel" id="panel-queries">';
      html += renderQueriesTable(queries);
      html += '</div>';
    }

    // Trace
    if (trace.length) {
      html += '<div class="tab-panel" id="panel-trace">';
      html += renderTrace(trace);
      html += '</div>';
    }

    // HTTP Calls
    if (httpCalls.length) {
      html += '<div class="tab-panel" id="panel-http_calls">';
      html += renderHttpCalls(httpCalls);
      html += '</div>';
    }

    // Autoloaded Options
    if (autoloadedOptions && autoloadedOptions.total_size) {
      html += '<div class="tab-panel" id="panel-options">';
      html += renderAutoloadedOptions(autoloadedOptions);
      html += '</div>';
    }

    // Enqueued Assets
    if (enqueuedAssets && ((enqueuedAssets.scripts || []).length || (enqueuedAssets.styles || []).length)) {
      html += '<div class="tab-panel" id="panel-assets">';
      html += renderEnqueuedAssets(enqueuedAssets);
      html += '</div>';
    }

    // Diagnostics
    if (diagnostics) {
      html += '<div class="tab-panel" id="panel-diagnostics">';
      html += renderDiagnostics(diagnostics);
      html += '</div>';
    }

    // Security footer
    html += '<div class="security-footer">';
    html += '🔒 This report was decrypted entirely in your browser. The server never sees the contents.<br>';
    html += '<a href="https://scrutineer.dev/scrutinizer">Scrutinizer</a> — WordPress Performance Profiler';
    html += '</div>';

    app.innerHTML = html;

    // Guidance dismiss button (avoids inline onclick quoting issues in template literal).
    var dismissBtn = document.getElementById('dismiss-guidance');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', function() {
        var g = document.getElementById('guidance');
        if (g) g.remove();
        localStorage.setItem('scrutinizer-guidance-dismissed', '1');
      });
    }

    // Tab switching via delegation (avoids inline onclick quoting issues).
    var tabBar = document.querySelector('.tab-bar');
    if (tabBar) {
      tabBar.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-tab]');
        if (!btn) return;
        switchTab(btn.dataset.tab);
      });
    }

    // Query view interactions (delegated).
    document.addEventListener('click', function(e) {
      // Grouped/Individual toggle.
      var togBtn = e.target.closest('.toggle-btn');
      if (togBtn) {
        var view = togBtn.dataset.view;
        document.querySelectorAll('.toggle-btn').forEach(function(b) { b.classList.remove('active'); });
        togBtn.classList.add('active');
        document.querySelectorAll('.queries-view').forEach(function(v) { v.style.display = 'none'; });
        var target = document.getElementById('queries-' + view);
        if (target) target.style.display = '';
        return;
      }

      // Expand grouped row.
      var groupRow = e.target.closest('.group-row');
      if (groupRow && !e.target.closest('.sql-expandable') && !e.target.closest('.sql-full')) {
        var sql = groupRow.dataset.sql;
        groupRow.classList.toggle('is-expanded');
        document.querySelectorAll('.group-detail').forEach(function(d) {
          if (d.dataset.sql === sql) d.style.display = d.style.display === 'none' ? '' : 'none';
        });
        return;
      }

      // Click-to-expand SQL.
      var sqlExp = e.target.closest('.sql-expandable');
      if (sqlExp) {
        e.stopPropagation();
        var full = sqlExp.parentElement.querySelector('.sql-full');
        if (full) { sqlExp.style.display = 'none'; full.style.display = ''; }
        return;
      }
      var sqlFull = e.target.closest('.sql-full');
      if (sqlFull) {
        e.stopPropagation();
        var short = sqlFull.parentElement.querySelector('.sql-expandable');
        if (short) { sqlFull.style.display = 'none'; short.style.display = ''; }
        return;
      }

      // Source pill filter.
      var pill = e.target.closest('.query-source-pill') || e.target.closest('.query-filter-pill');
      if (pill) {
        e.stopPropagation();
        var src = pill.dataset.source;
        var bar = document.querySelector('.query-filter-bar');
        if (bar) { bar.style.display = ''; bar.querySelector('.filter-source-name').textContent = src; }
        document.querySelectorAll('.query-ind-row').forEach(function(r) {
          r.style.display = r.dataset.source === src ? '' : 'none';
        });
        document.querySelectorAll('.group-row').forEach(function(r) {
          var pills = r.querySelectorAll('.source-badge');
          var match = false;
          pills.forEach(function(p) { if (p.textContent.trim() === src) match = true; });
          r.style.display = match ? '' : 'none';
          var sql2 = r.dataset.sql;
          document.querySelectorAll('.group-detail').forEach(function(d) {
            if (d.dataset.sql === sql2) d.style.display = match ? 'none' : 'none';
          });
        });
        return;
      }

      // Clear filter.
      if (e.target.closest('.clear-filter')) {
        var bar2 = document.querySelector('.query-filter-bar');
        if (bar2) bar2.style.display = 'none';
        document.querySelectorAll('.query-ind-row, .group-row').forEach(function(r) { r.style.display = ''; });
        document.querySelectorAll('.group-detail').forEach(function(d) { d.style.display = 'none'; });
        return;
      }
    });

    // Zoom/pan controls for timeline.
    (function() {
      var wrapper = document.querySelector('.timeline-zoom-wrapper');
      var viewport = document.querySelector('.timeline-viewport');
      var zoomIn = document.querySelector('.zoom-in-btn');
      var zoomOut = document.querySelector('.zoom-out-btn');
      var zoomReset = document.querySelector('.zoom-reset-btn');
      var zoomLabel = document.querySelector('.timeline-zoom-level');
      if (!wrapper || !viewport) return;

      var zoom = 1;
      var maxZoom = 10;

      function applyZoom() {
        wrapper.style.width = (zoom * 100) + '%';
        if (zoomLabel) zoomLabel.textContent = zoom.toFixed(zoom >= 2 ? 0 : 1) + 'x';
      }

      if (zoomIn) zoomIn.addEventListener('click', function() {
        zoom = Math.min(zoom * 1.5, maxZoom);
        applyZoom();
      });
      if (zoomOut) zoomOut.addEventListener('click', function() {
        zoom = Math.max(zoom / 1.5, 1);
        applyZoom();
      });
      if (zoomReset) zoomReset.addEventListener('click', function() {
        zoom = 1;
        applyZoom();
        viewport.scrollLeft = 0;
      });

      // Scroll-to-zoom (no modifier key needed).
      viewport.addEventListener('wheel', function(e) {
        e.preventDefault();
        var rect = viewport.getBoundingClientRect();
        var mouseX = e.clientX - rect.left + viewport.scrollLeft;
        var oldZoom = zoom;
        if (e.deltaY < 0) {
          zoom = Math.min(zoom * 1.3, maxZoom);
        } else {
          zoom = Math.max(zoom / 1.3, 1);
        }
        applyZoom();
        // Keep point under cursor stable.
        var newScrollLeft = mouseX * (zoom / oldZoom) - (e.clientX - rect.left);
        viewport.scrollLeft = Math.max(0, newScrollLeft);
      }, { passive: false });

      // Rubber band select (at 1x) or drag to pan (when zoomed).
      var dragging = false;
      var rubberBanding = false;
      var startX = 0;
      var startScroll = 0;
      var rubberBandStartX = 0;
      var rubberBandEl = document.createElement('div');
      rubberBandEl.className = 'rubber-band';
      viewport.appendChild(rubberBandEl);

      viewport.addEventListener('mousedown', function(e) {
        if (e.button !== 0) return;
        if (e.target.classList.contains('timeline-segment')) return;
        e.preventDefault();
        var rect = viewport.getBoundingClientRect();
        if (zoom <= 1) {
          rubberBanding = true;
          rubberBandStartX = e.clientX - rect.left;
          rubberBandEl.style.left = rubberBandStartX + 'px';
          rubberBandEl.style.width = '0px';
          rubberBandEl.style.display = 'block';
          viewport.style.cursor = 'col-resize';
        } else {
          dragging = true;
          startX = e.clientX;
          startScroll = viewport.scrollLeft;
          viewport.style.cursor = 'grabbing';
        }
      });
      document.addEventListener('mousemove', function(e) {
        if (rubberBanding) {
          var rect = viewport.getBoundingClientRect();
          var currentX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
          var left = Math.min(rubberBandStartX, currentX);
          var width = Math.abs(currentX - rubberBandStartX);
          rubberBandEl.style.left = left + 'px';
          rubberBandEl.style.width = width + 'px';
          return;
        }
        if (!dragging) return;
        viewport.scrollLeft = startScroll - (e.clientX - startX);
      });
      document.addEventListener('mouseup', function(e) {
        if (rubberBanding) {
          rubberBanding = false;
          rubberBandEl.style.display = 'none';
          viewport.style.cursor = '';
          var rect = viewport.getBoundingClientRect();
          var endX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
          var left = Math.min(rubberBandStartX, endX);
          var width = Math.abs(endX - rubberBandStartX);
          if (width < 10) return;
          var viewportW = rect.width;
          var selStartPct = left / viewportW;
          var selWidthPct = width / viewportW;
          zoom = Math.min(1 / selWidthPct, maxZoom);
          applyZoom();
          viewport.scrollLeft = selStartPct * viewportW * zoom;
          return;
        }
        if (dragging) {
          dragging = false;
          viewport.style.cursor = '';
        }
      });
    })();
  }

  // Tab switching
  window.switchTab = function(tabId) {
    document.querySelectorAll('.tab-bar button').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + tabId));
  };

  // Render helpers
  function metricCard(label, value, sub) {
    return '<div class="metric-card"><div class="label">' + escHtml(label) + '</div>' +
      '<div class="value">' + escHtml(value) + '</div>' +
      (sub ? '<div class="sub">' + escHtml(sub) + '</div>' : '') + '</div>';
  }

  function renderTimeline(timeline, milestones, totalMs, httpCalls, queries, sources) {
    if (!totalMs) return '<p style="color:var(--text-muted)">No timeline data.</p>';

    var durationNs = totalMs * 1e6;
    var html = '<div class="timeline-container">';

    // Zoom controls.
    html += '<div class="timeline-zoom-controls">';
    html += '<button type="button" class="zoom-out-btn" title="Zoom out">&minus;</button>';
    html += '<span class="timeline-zoom-level">1&times;</span>';
    html += '<button type="button" class="zoom-in-btn" title="Zoom in">+</button>';
    html += '<button type="button" style="width:auto;padding:0 10px" class="zoom-reset-btn" title="Reset zoom">Reset</button>';
    html += '<span class="timeline-zoom-hint">Drag to select &middot; Scroll to zoom</span>';
    html += '</div>';

    // Scrollable viewport.
    html += '<div class="timeline-viewport">';
    html += '<div class="timeline-zoom-wrapper">';

    // Phase milestones — lollipop stems above the bar.
    var labelPositions = [];
    for (var m = 0; m < milestones.length; m++) {
      var marker = milestones[m];
      var markerPct = (marker.offset_ms / totalMs) * 100;
      if (markerPct > 100) markerPct = 100;
      labelPositions.push({ pct: markerPct, name: marker.label || marker.hook || '' });
    }
    // Assign tiers to prevent horizontal label overlap.
    var labelTiers = [];
    for (var li = 0; li < labelPositions.length; li++) {
      var tier = 0;
      for (var lj = 0; lj < li; lj++) {
        if (Math.abs(labelPositions[li].pct - labelPositions[lj].pct) < 8 && labelTiers[lj] >= tier) {
          tier = labelTiers[lj] + 1;
        }
      }
      labelTiers.push(tier);
    }
    var maxTier = 0;
    for (var lt = 0; lt < labelTiers.length; lt++) {
      if (labelTiers[lt] > maxTier) maxTier = labelTiers[lt];
    }
    var tierPx = 32;
    var baseOffset = 20;
    var milestoneHeight = labelPositions.length > 0 ? (maxTier + 1) * tierPx + baseOffset + 16 : 0;

    if (labelPositions.length > 0) {
      html += '<div class="milestones" style="height:' + milestoneHeight + 'px">';
      for (var lk = 0; lk < labelPositions.length; lk++) {
        var stemHeight = (labelTiers[lk] + 1) * tierPx + baseOffset;
        var leftPct = labelPositions[lk].pct.toFixed(2);
        var pctVal = labelPositions[lk].pct;
        var edgeCls = '';
        if (pctVal > 85) {
          edgeCls = ' milestone-right';
        } else if (pctVal < 15) {
          edgeCls = ' milestone-left';
        }
        html += '<div class="milestone' + edgeCls + '" style="left:' + leftPct + '%;height:' + stemHeight + 'px">';
        html += '<span class="milestone-label">' + escHtml(labelPositions[lk].name) + '</span>';
        html += '<span class="milestone-dot"></span>';
        html += '<span class="milestone-stem"></span>';
        html += '</div>';
      }
      html += '</div>';
    }

    // Timeline bar.
    html += '<div class="timeline-bar">';
    for (var i = 0; i < timeline.length; i++) {
      var seg = timeline[i];
      var segPctW = seg.pct_width || ((seg.duration_ms || 0) / totalMs * 100);
      var segPctS = seg.pct_start != null ? seg.pct_start : ((seg.offset_ms || 0) / totalMs * 100);
      if (segPctW < 0.05) continue;
      var segColor = getSourceColor(seg.source || '', seg.source_type || 'unknown');
      var segTitle = escAttr((seg.callback || seg.source || '') + ' \u00b7 ' + formatMs(seg.duration_ms || 0));
      html += '<div class="segment" style="left:' + segPctS.toFixed(3) + '%;width:' + Math.max(segPctW, 0.15).toFixed(3) + '%;background:' + segColor + '" title="' + segTitle + '"></div>';
    }

    // Memory usage sparkline — overlay on the timeline bar.
    var memPoints = [];
    for (var mi = 0; mi < timeline.length; mi++) {
      var memVal = timeline[mi].mem_after || 0;
      if (memVal > 0) {
        var memPctX = (timeline[mi].pct_start || 0) + (timeline[mi].pct_width || 0);
        memPoints.push({ pct: memPctX, mem: memVal });
      }
    }
    if (memPoints.length >= 2) {
      var memMin = memPoints[0].mem;
      var memMax = memPoints[0].mem;
      for (var mm = 1; mm < memPoints.length; mm++) {
        if (memPoints[mm].mem < memMin) memMin = memPoints[mm].mem;
        if (memPoints[mm].mem > memMax) memMax = memPoints[mm].mem;
      }
      var memRange = memMax - memMin;
      if (memRange > memMax * 0.01) {
        var pathD = '';
        for (var mp = 0; mp < memPoints.length; mp++) {
          var sx = memPoints[mp].pct;
          var sy = 100 - ((memPoints[mp].mem - memMin) / memRange) * 80 - 10;
          pathD += (mp === 0 ? 'M' : 'L') + sx.toFixed(2) + ',' + sy.toFixed(1) + ' ';
        }
        var memLabel = formatBytes(memMax) + ' peak';
        var memMinLabel = formatBytes(memMin);
        var memTitle = 'Memory: ' + memMinLabel + ' &#x2192; ' + memLabel;
        html += '<svg class="memory-overlay-svg" viewBox="0 0 100 100" preserveAspectRatio="none">';
        html += '<title>' + escHtml(memTitle) + '</title>';
        html += '<path d="' + pathD + '" fill="none" stroke="transparent" stroke-width="10" vector-effect="non-scaling-stroke" class="memory-hit-area"/>';
        html += '<path d="' + pathD + '" fill="none" stroke="rgba(230,126,34,0.7)" stroke-width="2" vector-effect="non-scaling-stroke" class="memory-line"/>';
        html += '</svg>';
        html += '<span class="memory-overlay-label">' + escHtml(memLabel) + '</span>';
      }
    }

    html += '</div>';

    // Time axis — 5 evenly spaced ticks.
    html += '<div class="timeline-axis">';
    var tickCount = 5;
    for (var k = 0; k <= tickCount; k++) {
      var tickMs = (totalMs * k / tickCount).toFixed(0);
      var tickPct = (k / tickCount) * 100;
      html += '<span class="tick" style="left:' + tickPct + '%">' + tickMs + ' ms</span>';
    }
    html += '</div>';

    // HTTP call lollipops — below the bar (inverted stems).
    if (httpCalls && httpCalls.length > 0) {
      var httpPositions = [];
      for (var hi = 0; hi < httpCalls.length; hi++) {
        var hc = httpCalls[hi];
        var hPct = hc.offset_ms != null ? (hc.offset_ms / totalMs) * 100 : -1;
        if (hPct < 0 || hPct > 100) continue;
        httpPositions.push({ pct: hPct, call: hc });
      }
      if (httpPositions.length > 0) {
        var httpTiers = [];
        for (var hti = 0; hti < httpPositions.length; hti++) {
          var hTier = 0;
          for (var htj = 0; htj < hti; htj++) {
            if (Math.abs(httpPositions[hti].pct - httpPositions[htj].pct) < 8 && httpTiers[htj] >= hTier) {
              hTier = httpTiers[htj] + 1;
            }
          }
          httpTiers.push(hTier);
        }
        var httpMaxTier = 0;
        for (var hmt = 0; hmt < httpTiers.length; hmt++) {
          if (httpTiers[hmt] > httpMaxTier) httpMaxTier = httpTiers[hmt];
        }
        var httpTierPx = 32;
        var httpBaseOffset = 20;
        var httpHeight = (httpMaxTier + 1) * httpTierPx + httpBaseOffset + 16;
        html += '<div class="http-lollipops" style="height:' + httpHeight + 'px">';
        for (var hlk = 0; hlk < httpPositions.length; hlk++) {
          var hStemHeight = (httpTiers[hlk] + 1) * httpTierPx + httpBaseOffset;
          var hLeftPct = httpPositions[hlk].pct.toFixed(2);
          var hCall = httpPositions[hlk].call;
          var hDurMs = (hCall.duration_ms || 0).toFixed(0);
          var hHost = '';
          try { hHost = new URL(hCall.url).hostname; } catch(e) { hHost = hCall.url || ''; }
          var hStatusCls = '';
          if (hCall.is_error) {
            hStatusCls = ' http-error';
          } else if (hCall.status >= 400) {
            hStatusCls = ' http-error';
          }
          var hDotColor = '';
          if (hCall.is_error || (hCall.status && hCall.status >= 400)) {
            hDotColor = '#c44337';
          } else if (hCall.status >= 300) {
            hDotColor = '#dba617';
          } else if (hCall.source_name) {
            hDotColor = getSourceColor(hCall.source_name, hCall.source_type || 'unknown');
          } else {
            hDotColor = '#50575e';
          }
          var hTitle = (hCall.method || 'GET') + ' ' + (hCall.url || '') + '\\n' + hDurMs + ' ms';
          if (hCall.status) hTitle += ' \u2014 HTTP ' + hCall.status;
          if (hCall.caller) hTitle += '\\n' + hCall.caller;
          html += '<div class="http-lollipop' + hStatusCls + '" style="left:' + hLeftPct + '%;height:' + hStemHeight + 'px" title="' + escAttr(hTitle) + '">';
          html += '<span class="http-stem"></span>';
          html += '<span class="http-dot" style="background:' + hDotColor + '"></span>';
          html += '<span class="http-label">' + escHtml(truncateHost(hHost, 24)) + ' <em>' + hDurMs + 'ms</em></span>';
          html += '</div>';
        }
        html += '</div>';
      }
    }

    // Query density strip — thin heatmap showing where queries cluster.
    var timelineQueries = [];
    if (queries && queries.length > 0) {
      for (var qi = 0; qi < queries.length; qi++) {
        if (queries[qi].offset_ms != null) {
          timelineQueries.push(queries[qi]);
        }
      }
    }
    if (timelineQueries.length > 0) {
      var bucketCount = 60;
      var buckets = [];
      var bucketMaxMs = [];
      for (var bi = 0; bi < bucketCount; bi++) {
        buckets.push(0);
        bucketMaxMs.push(0);
      }
      for (var tqi = 0; tqi < timelineQueries.length; tqi++) {
        var bIdx = Math.floor((timelineQueries[tqi].offset_ms / totalMs) * bucketCount);
        if (bIdx >= bucketCount) bIdx = bucketCount - 1;
        if (bIdx < 0) bIdx = 0;
        buckets[bIdx]++;
        var tqMs = timelineQueries[tqi].time_ms || 0;
        if (tqMs > bucketMaxMs[bIdx]) bucketMaxMs[bIdx] = tqMs;
      }
      var maxCount = 1;
      for (var mc = 0; mc < buckets.length; mc++) {
        if (buckets[mc] > maxCount) maxCount = buckets[mc];
      }
      html += '<div class="query-density-wrap">';
      html += '<span class="density-label">Queries</span>';
      html += '<div class="query-density">';
      for (var db = 0; db < bucketCount; db++) {
        var fillPct = (buckets[db] / maxCount) * 100;
        var barCls = 'density-none';
        if (buckets[db] > 0) {
          barCls = 'density-normal';
          if (bucketMaxMs[db] >= 5) barCls = 'density-slow';
          else if (bucketMaxMs[db] >= 1) barCls = 'density-medium';
        }
        var dTitle = buckets[db] > 0 ? buckets[db] + ' quer' + (buckets[db] === 1 ? 'y' : 'ies') + ', slowest ' + bucketMaxMs[db].toFixed(1) + ' ms' : '';
        html += '<div class="density-bar ' + barCls + '" style="height:' + Math.max(fillPct, buckets[db] > 0 ? 20 : 0) + '%" title="' + escAttr(dTitle) + '"></div>';
      }
      html += '</div>';
      html += '</div>';
    }

    html += '</div>'; // timeline-zoom-wrapper
    html += '</div>'; // timeline-viewport

    // Legend — show all sources present in the timeline.
    if (sources && sources.length > 0) {
      html += '<div class="timeline-legend">';
      var legendSorted = [...sources].sort(function(a, b) { return (b.exclusive_ms || 0) - (a.exclusive_ms || 0); });
      legendSorted.forEach(function(src) {
        var color = getSourceColor(src.source || src.name || '', src.type || 'unknown');
        html += '<div class="timeline-legend-item"><div class="timeline-legend-swatch" style="background:' + color + '"></div>' +
          escHtml(src.source || src.name) + '</div>';
      });
      html += '</div>';
    }

    // I/O summary counts below timeline.
    var queryCount = queries ? queries.length : 0;
    var httpCount = httpCalls ? httpCalls.length : 0;
    if (queryCount > 0 || httpCount > 0) {
      var parts = [];
      if (queryCount > 0) parts.push(queryCount + ' quer' + (queryCount === 1 ? 'y' : 'ies'));
      if (httpCount > 0) parts.push(httpCount + ' HTTP call' + (httpCount === 1 ? '' : 's'));
      html += '<div style="font-size:0.8rem;color:var(--text-dim);margin-top:8px;text-align:center">' + parts.join(' \u00b7 ') + '</div>';
    }

    html += '</div>'; // timeline-container
    return html;
  }

  function renderBreakdownBar(sources, totalMs) {
    if (!totalMs) return '';
    var sorted = [...sources].sort(function(a, b) { return (b.exclusive_ms || 0) - (a.exclusive_ms || 0); });

    var html = '<div class="breakdown-bar">';
    sorted.forEach(function(src) {
      var pct = ((src.exclusive_ms || 0) / totalMs * 100).toFixed(2);
      if (parseFloat(pct) < 0.1) return;
      var color = getSourceColor(src.source || src.name || '', src.type || 'unknown');
      html += '<div class="breakdown-segment" style="width:' + pct + '%;background:' + color + '">' +
        '<div class="tooltip">' + escHtml(src.source || src.name) + ': ' + formatMs(src.exclusive_ms || 0) + ' (' + pct + '%)</div></div>';
    });
    html += '</div>';
    return html;
  }

  function renderLegend(sources) {
    var sorted = [...sources].sort(function(a, b) { return (b.exclusive_ms || 0) - (a.exclusive_ms || 0); });
    var html = '<div class="legend">';
    sorted.forEach(function(src) {
      var color = getSourceColor(src.source || src.name || '', src.type || 'unknown');
      html += '<div class="legend-item"><div class="legend-swatch" style="background:' + color + '"></div>' +
        escHtml(src.source || src.name) + '</div>';
    });
    html += '</div>';
    return html;
  }

  function renderSourcesTable(sources, totalMs) {
    var sorted = [...sources].sort(function(a, b) { return (b.exclusive_ms || 0) - (a.exclusive_ms || 0); });

    var html = '<table class="data-table"><thead><tr>' +
      '<th>Source</th><th>Type</th><th class="num">Exclusive</th><th class="num">%</th>' +
      '<th class="num">Inclusive</th><th class="num">Callbacks</th></tr></thead><tbody>';

    sorted.forEach(function(src) {
      var color = getSourceColor(src.source || src.name || '', src.type || 'unknown');
      var pct = totalMs ? ((src.exclusive_ms || 0) / totalMs * 100).toFixed(1) : '\u2014';
      html += '<tr><td>' +
        '<span class="source-badge" style="background:' + color + '22;color:' + color + '">' + escHtml(src.source || src.name) + '</span>' +
        '<div class="weight-bar" style="width:' + pct + '%;background:' + color + '"></div>' +
        '</td>' +
        '<td>' + escHtml(src.type || '') + '</td>' +
        '<td class="num">' + formatMs(src.exclusive_ms || 0) + '</td>' +
        '<td class="num">' + pct + '%</td>' +
        '<td class="num">' + formatMs(src.inclusive_ms || 0) + '</td>' +
        '<td class="num">' + (src.callback_count || 0) + '</td></tr>';
    });

    html += '</tbody></table>';
    return html;
  }

  function renderQueriesTable(queries) {
    if (!queries || !queries.length) return '<p style="color:var(--text-muted)">No query data captured.</p>';

    // Per-source summary. Null-prototype map: source names come from the
    // (attacker-authored) report, so keys like "__proto__" must not reach
    // Object.prototype or abort rendering.
    const bySrc = Object.create(null);
    let totalMs = 0;
    queries.forEach(q => {
      totalMs += q.time_ms || 0;
      const sn = q.source || '\u2014';
      const st = q.source_type || 'unknown';
      if (!bySrc[sn]) bySrc[sn] = { name: sn, type: st, count: 0, time: 0 };
      bySrc[sn].count++;
      bySrc[sn].time += q.time_ms || 0;
    });
    const srcList = Object.values(bySrc).sort((a, b) => b.time - a.time);

    // Group by SQL pattern (null-prototype: keys are report-controlled SQL).
    const groups = Object.create(null);
    const groupOrder = [];
    queries.forEach(q => {
      const key = q.sql || '';
      if (!groups[key]) { groups[key] = { sql: key, items: [], totalMs: 0 }; groupOrder.push(key); }
      groups[key].items.push(q);
      groups[key].totalMs += q.time_ms || 0;
    });
    let dupCount = 0;
    groupOrder.forEach(k => { if (groups[k].items.length > 1) dupCount++; });

    let html = '<div class="queries-header">';
    html += '<div class="queries-summary"><strong>' + queries.length + ' queries</strong> totaling <strong>' + formatMs(totalMs) + '</strong>';
    if (dupCount > 0) html += ' &middot; <span class="duplicate-flag">' + dupCount + ' duplicate pattern' + (dupCount !== 1 ? 's' : '') + '</span>';
    html += '</div>';

    // Source pills
    html += '<div class="queries-sources">';
    srcList.forEach(s => {
      const color = SOURCE_COLORS[s.type] || SOURCE_COLORS.unknown;
      html += '<button type="button" class="query-source-pill" data-source="' + escAttr(s.name) + '" style="background:' + color + '">' +
        escHtml(s.name) + ': ' + s.count + ' (' + formatMs(s.time) + ')</button>';
    });
    html += '</div>';

    // Toggle
    html += '<div class="queries-toggle">' +
      '<button type="button" class="toggle-btn active" data-view="grouped">Grouped</button>' +
      '<button type="button" class="toggle-btn" data-view="individual">Individual</button></div>';
    html += '</div>';

    // Filter bar (hidden)
    html += '<div class="query-filter-bar" style="display:none">Showing queries from <strong class="filter-source-name"></strong> ' +
      '<button type="button" class="clear-filter">\u2715 Clear</button></div>';

    // Grouped view
    html += '<div class="queries-view" id="queries-grouped">';
    html += renderQueriesGrouped(groups, groupOrder);
    html += '</div>';

    // Individual view
    html += '<div class="queries-view" id="queries-individual" style="display:none">';
    html += renderQueriesIndividual(queries);
    html += '</div>';

    return html;
  }

  function renderQueriesGrouped(groups, groupOrder) {
    const sorted = [...groupOrder].sort((a, b) => groups[b].totalMs - groups[a].totalMs);
    let html = '<table class="data-table"><thead><tr><th>SQL Pattern</th><th class="num">Count</th><th class="num">Total</th><th class="num">Avg</th><th>Sources</th></tr></thead><tbody>';

    sorted.forEach(key => {
      const grp = groups[key];
      const avg = grp.totalMs / grp.items.length;
      const isDup = grp.items.length > 1;
      const rowCls = grp.totalMs > 50 ? ' slow-row' : '';

      // Unique sources
      const srcs = {};
      grp.items.forEach(q => { srcs[q.source || '\u2014'] = q.source_type || 'unknown'; });

      html += '<tr class="group-row' + rowCls + '" data-sql="' + escAttr(grp.sql) + '">';
      html += '<td class="mono"><span class="sql-expandable" title="Click to expand">' + escHtml(grp.sql.length > 120 ? grp.sql.substring(0, 120) + '...' : grp.sql) + '</span>';
      if (grp.sql.length > 120) html += '<span class="sql-full" style="display:none">' + escHtml(grp.sql) + '</span>';
      html += '</td>';
      html += '<td class="num">' + (isDup ? '<span class="duplicate-badge">\u00d7' + grp.items.length + '</span>' : '1') + '</td>';
      html += '<td class="num">' + formatMs(grp.totalMs) + '</td>';
      html += '<td class="num">' + formatMs(avg) + '</td>';
      html += '<td>';
      Object.entries(srcs).forEach(([name, type]) => {
        const color = SOURCE_COLORS[type] || SOURCE_COLORS.unknown;
        html += '<span class="source-badge" style="background:' + color + '22;color:' + color + '">' + escHtml(name) + '</span> ';
      });
      html += '</td></tr>';

      if (isDup) {
        html += '<tr class="group-detail" data-sql="' + escAttr(grp.sql) + '" style="display:none"><td colspan="5">';
        html += '<table class="group-detail-table"><thead><tr><th>#</th><th>Source</th><th>Time</th><th>Caller</th></tr></thead><tbody>';
        grp.items.forEach((q, i) => {
          const color = SOURCE_COLORS[q.source_type] || SOURCE_COLORS.unknown;
          html += '<tr><td>' + (i + 1) + '</td>';
          html += '<td><span class="source-badge" style="background:' + color + '22;color:' + color + '">' + escHtml(q.source || '\u2014') + '</span></td>';
          html += '<td class="num">' + formatMs(q.time_ms || 0) + '</td>';
          html += '<td class="mono" style="font-size:0.75rem;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escAttr(q.caller || '') + '">' + escHtml(q.caller || '\u2014') + '</td></tr>';
        });
        html += '</tbody></table></td></tr>';
      }
    });

    html += '</tbody></table>';
    return html;
  }

  function renderQueriesIndividual(queries) {
    const sorted = [...queries].sort((a, b) => (b.time_ms || 0) - (a.time_ms || 0));
    const top = sorted.slice(0, 100);

    let html = '<table class="data-table"><thead><tr>' +
      '<th>Query</th><th class="num">Time</th><th>Source</th></tr></thead><tbody>';

    top.forEach(q => {
      const rowCls = (q.time_ms || 0) > 50 ? ' slow-row' : '';
      const timeCls = (q.time_ms || 0) > 50 ? ' slow' : ((q.time_ms || 0) > 10 ? ' warn' : '');
      const color = SOURCE_COLORS[q.source_type] || SOURCE_COLORS.unknown;
      html += '<tr class="query-ind-row' + rowCls + '" data-source="' + escAttr(q.source || '') + '">' +
        '<td class="mono"><span class="sql-expandable" title="Click to expand">' + escHtml(q.sql && q.sql.length > 120 ? q.sql.substring(0, 120) + '...' : (q.sql || '')) + '</span>' +
        (q.sql && q.sql.length > 120 ? '<span class="sql-full" style="display:none">' + escHtml(q.sql) + '</span>' : '') + '</td>' +
        '<td class="num' + timeCls + '">' + formatMs(q.time_ms || 0) + '</td>' +
        '<td>' + (q.source ? '<span class="source-badge query-filter-pill" data-source="' + escAttr(q.source) + '" style="cursor:pointer;background:' + color + '22;color:' + color + '">' + escHtml(q.source) + '</span>' : '') + '</td></tr>';
    });

    html += '</tbody></table>';
    if (sorted.length > 100) {
      html += '<p style="font-size:0.8rem;color:var(--text-dim);margin-top:0.5rem;">Showing top 100 of ' + sorted.length + ' queries.</p>';
    }
    return html;
  }

  function renderTrace(trace) {
    let html = '<div class="trace-tree">';

    // Group by phase if available (null-prototype: phase is report-controlled).
    const phases = Object.create(null);
    trace.forEach(item => {
      const phase = item.phase || 'other';
      if (!phases[phase]) phases[phase] = [];
      phases[phase].push(item);
    });

    Object.entries(phases).forEach(([phase, items]) => {
      const totalPhaseMs = items.reduce((s, i) => s + (i.exclusive_ms || 0), 0);
      html += '<details class="trace-phase"><summary>' + escHtml(phase) +
        ' <span style="color:var(--text-dim);font-size:0.8rem">(' + items.length + ' callbacks)</span>' +
        '<span class="phase-time">' + formatMs(totalPhaseMs) + '</span></summary>';
      html += '<div class="trace-callbacks">';
      items.slice(0, 200).forEach(item => {
        const color = SOURCE_COLORS[item.source_type] || SOURCE_COLORS.unknown;
        html += '<div class="trace-callback">' +
          '<span class="cb-source" style="background:' + color + '22;color:' + color + '">' + escHtml(item.source || '') + '</span>' +
          '<span class="cb-name">' + escHtml(item.callback || '') + '</span>' +
          '<span class="cb-time">' + formatMs(item.exclusive_ms || 0) + '</span></div>';
      });
      if (items.length > 200) {
        html += '<div style="padding:0.5rem;font-size:0.8rem;color:var(--text-dim)">… and ' + (items.length - 200) + ' more</div>';
      }
      html += '</div></details>';
    });

    html += '</div>';
    return html;
  }

  function renderDiagnostics(diag) {
    let html = '<div class="diagnostics-grid">';

    if (diag.site) {
      html += '<div class="diag-section"><h3>Environment</h3>';
      Object.entries(diag.site).forEach(([k, v]) => {
        html += '<div class="diag-row"><span class="diag-key">' + escHtml(humanize(k)) + '</span>' +
          '<span class="diag-val">' + escHtml(String(v)) + '</span></div>';
      });
      html += '</div>';
    }

    if (diag.plugins) {
      html += '<div class="diag-section"><h3>Plugins (' + (diag.plugins.active_count || 0) + ' active)</h3>';
      (diag.plugins.active || []).forEach(p => {
        html += '<div class="diag-row"><span class="diag-val">' + escHtml(p) + '</span></div>';
      });
      html += '</div>';
    }

    if (diag.theme) {
      html += '<div class="diag-section"><h3>Theme</h3>';
      html += '<div class="diag-row"><span class="diag-key">Active</span><span class="diag-val">' + escHtml(diag.theme.slug || '') + '</span></div>';
      if (diag.theme.parent) {
        html += '<div class="diag-row"><span class="diag-key">Parent</span><span class="diag-val">' + escHtml(diag.theme.parent) + '</span></div>';
      }
      html += '</div>';
    }

    if (diag.scale) {
      html += '<div class="diag-section"><h3>Scale</h3>';
      Object.entries(diag.scale).forEach(([k, v]) => {
        html += '<div class="diag-row"><span class="diag-key">' + escHtml(humanize(k)) + '</span>' +
          '<span class="diag-val">' + escHtml(String(v)) + '</span></div>';
      });
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  function renderHttpCalls(httpCalls) {
    if (!httpCalls || !httpCalls.length) return '<p style="color:var(--text-muted)">No HTTP calls captured.</p>';

    const sorted = [...httpCalls].sort((a, b) => (b.duration_ms || 0) - (a.duration_ms || 0));

    let html = '<table class="data-table">';
    html += '<thead><tr><th>URL</th><th>Method</th><th>Status</th><th>Source</th><th class="num">Duration</th></tr></thead>';
    html += '<tbody>';
    sorted.forEach(h => {
      const color = SOURCE_COLORS[h.source_type] || SOURCE_COLORS.unknown;
      const statusClass = h.is_error || (h.status >= 400) ? ' slow' : '';
      html += '<tr>';
      html += '<td class="mono" style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escAttr(String(h.url || '')) + '">' + escHtml(String(h.url || '')) + '</td>';
      html += '<td>' + escHtml(h.method) + '</td>';
      html += '<td' + (statusClass ? ' class="' + statusClass + '"' : '') + '>' + escHtml(String(h.status || '—')) + '</td>';
      html += '<td><span class="source-badge" style="background:' + color + '22;color:' + color + '">' + escHtml(h.source_name || 'unknown') + '</span></td>';
      html += '<td class="num">' + formatMs(h.duration_ms || 0) + '</td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    return html;
  }

  function renderAutoloadedOptions(options) {
    if (!options) return '<p style="color:var(--text-muted)">No autoloaded options data.</p>';

    let html = '';
    if (options.total_size) {
      html += '<div class="metrics" style="margin-bottom:1rem"><div class="metric-card"><div class="label">Total Autoload Size</div><div class="value">' + formatBytes(options.total_size) + '</div></div></div>';
    }

    if (options.items && options.items.length) {
      const sorted = [...options.items].sort((a, b) => (b.size || 0) - (a.size || 0));
      html += '<table class="data-table">';
      html += '<thead><tr><th>Option</th><th>Source</th><th class="num">Size</th></tr></thead>';
      html += '<tbody>';
      sorted.forEach(opt => {
        html += '<tr>';
        html += '<td class="mono">' + escHtml(opt.name || '') + '</td>';
        html += '<td>' + escHtml(opt.source || '') + '</td>';
        html += '<td class="num">' + formatBytes(opt.size || 0) + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
    }

    return html || '<p style="color:var(--text-muted)">No option details available.</p>';
  }

  function renderEnqueuedAssets(assets) {
    if (!assets) return '<p style="color:var(--text-muted)">No enqueued assets data.</p>';

    function assetRow(s) {
      var sourcePill = '';
      if (s.attribution && s.attribution.type && s.attribution.type !== 'unknown') {
        var pillColor = getSourceColor(s.attribution.name || s.attribution.slug || '', s.attribution.type);
        sourcePill = '<span class="asset-source-pill" style="background:' + pillColor + '">' + escHtml(s.attribution.name || s.attribution.slug || '') + '</span>';
      }
      var srcUrl = s.src || '';
      var srcDisplay = srcUrl;
      try { srcDisplay = new URL(srcUrl).pathname + new URL(srcUrl).search; } catch(e) {}
      if (srcDisplay.length > 60) srcDisplay = srcDisplay.substring(0, 59) + '\u2026';
      return '<tr><td>' + sourcePill + '<code class="mono">' + escHtml(s.handle || '') + '</code></td>' +
        '<td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escAttr(srcUrl) + '">' + escHtml(srcDisplay) + '</td>' +
        '<td class="num">' + (s.size > 0 ? formatBytes(s.size) : '<span style="color:var(--text-dim)">external</span>') + '</td>' +
        '<td>' + escHtml(s.location || '') + '</td></tr>';
    }

    var html = '';
    var scripts = assets.scripts || [];
    var styles = assets.styles || [];

    if (scripts.length) {
      html += '<h3 style="font-size:0.85rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:0.75rem">Scripts (' + scripts.length + ')</h3>';
      html += '<table class="data-table">';
      html += '<thead><tr><th>Handle</th><th>Source</th><th class="num">Size</th><th>Location</th></tr></thead>';
      html += '<tbody>';
      scripts.forEach(function(s) { html += assetRow(s); });
      html += '</tbody></table>';
    }

    if (styles.length) {
      html += '<h3 style="font-size:0.85rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;margin:1.5rem 0 0.75rem">Styles (' + styles.length + ')</h3>';
      html += '<table class="data-table">';
      html += '<thead><tr><th>Handle</th><th>Source</th><th class="num">Size</th><th>Location</th></tr></thead>';
      html += '<tbody>';
      styles.forEach(function(s) { html += assetRow(s); });
      html += '</tbody></table>';
    }

    return html || '<p style="color:var(--text-muted)">No asset details available.</p>';
  }

  function formatBytes(bytes) {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
  }

  // Utilities
  function formatMs(ms) {
    if (ms >= 1000) return (ms / 1000).toFixed(2) + 's';
    if (ms >= 10) return ms.toFixed(1) + 'ms';
    return ms.toFixed(2) + 'ms';
  }

  function formatDate(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString();
    } catch { return iso; }
  }

  function humanize(str) {
    return str.replace(/_/g, ' ').replace(/\\b\\w/g, c => c.toUpperCase());
  }

  function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function escAttr(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
      .replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Go
  init();
})();
</script>
</body>
</html>`;
