/**
 * Pure, dependency-free helpers for the relay Worker.
 *
 * Extracted from worker.js so they can be unit-tested directly (vitest) and
 * reused without dragging in the request handlers or the viewer template.
 * Nothing here touches R2, the Durable Object, or module state — only Web
 * platform globals (crypto, Response, btoa) available in both Workers and Node.
 */

export const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Revoke-Token',
  'Access-Control-Max-Age': '86400',
};

export const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

export const MAX_REPORT_SIZE = 10 * 1024 * 1024; // 10MB max ciphertext (R2 supports up to 5GB)
export const VALID_TTL_DAYS = [1, 7, 14, 30];
export const DEFAULT_TTL_DAYS = 7;

const RATE_LIMITER_SHARD_COUNT = 16;

// Build the CSP. The viewer is the only page with an inline <script>; it is
// served with a per-response nonce so the script runs while 'unsafe-inline' is
// dropped. Every other response has no script and falls back to script-src
// 'none', so any unescaped report content is inert rather than executable.
export function buildCSP(scriptSrc) {
  return "default-src 'none'; script-src " + scriptSrc +
    "; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
}

// Generate a 128-bit base64 nonce for the viewer's inline <script>.
export function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function withSecurityHeaders(response) {
  const resp = new Response(response.body, response);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    resp.headers.set(k, v);
  }
  // A handler serving inline script passes its nonce via the internal
  // X-CSP-Nonce header; promote it into the CSP and strip it from the response.
  const nonce = resp.headers.get('X-CSP-Nonce');
  if (nonce) {
    resp.headers.delete('X-CSP-Nonce');
    resp.headers.set('Content-Security-Policy', buildCSP("'nonce-" + nonce + "'"));
  } else {
    resp.headers.set('Content-Security-Policy', buildCSP("'none'"));
  }
  return resp;
}

/**
 * Constant-time string comparison. The revoke token is a fixed-length 256-bit
 * value, so comparing lengths first does not leak useful information.
 */
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * HMAC-SHA256 hash an IP address for pseudonymous rate limiting.
 *
 * No hardcoded fallback salt: a known public salt makes the hash trivially
 * reversible over the IPv4 space, defeating the GDPR pseudonymization claim.
 * Without a configured secret we return null and let rate limiting fail open
 * (it is not a security boundary — see D28), so no weakly-hashed IP exists.
 *
 * Returns the first 16 hex chars — enough for uniqueness, not reversible.
 */
export async function hashIP(ip, env) {
  const secret = env && env.IP_HASH_SECRET;
  if (!secret) {
    return null;
  }
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(ip));
  const bytes = new Uint8Array(sig);
  let hex = '';
  for (let i = 0; i < 8; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function shardKeyFromIP(hashedIp) {
  // IP is already HMAC-hashed at this point. Simple char-code hash for shard selection.
  let hash = 0;
  for (let i = 0; i < hashedIp.length; i++) {
    hash = ((hash << 5) - hash + hashedIp.charCodeAt(i)) | 0;
  }
  return `shard-${Math.abs(hash) % RATE_LIMITER_SHARD_COUNT}`;
}

/**
 * JSON response helper.
 */
export function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS,
      ...extraHeaders,
    }
  });
}
