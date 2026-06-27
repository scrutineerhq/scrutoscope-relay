import { describe, it, expect } from 'vitest';
import {
  hashIP,
  shardKeyFromIP,
  buildCSP,
  generateNonce,
  timingSafeEqual,
  withSecurityHeaders,
} from '../src/lib.js';

describe('buildCSP', () => {
  it('never allows unsafe-inline for scripts and uses default-src none', () => {
    const csp = buildCSP("'none'");
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'none'");
    expect(csp).not.toContain('unsafe-inline; '); // not in script-src
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
  });

  it('threads a nonce into script-src', () => {
    expect(buildCSP("'nonce-abc'")).toContain("script-src 'nonce-abc'");
  });
});

describe('generateNonce', () => {
  it('returns a 128-bit base64 value and is unique per call', () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toBe(b);
    // 16 bytes -> 24 base64 chars (with padding).
    expect(atob(a).length).toBe(16);
  });
});

describe('timingSafeEqual', () => {
  it('matches equal strings and rejects differing or unequal-length ones', () => {
    expect(timingSafeEqual('abc123', 'abc123')).toBe(true);
    expect(timingSafeEqual('abc123', 'abc124')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
    expect(timingSafeEqual(null, 'x')).toBe(false);
  });
});

describe('withSecurityHeaders', () => {
  it('applies security headers and falls back to script-src none', () => {
    const resp = withSecurityHeaders(new Response('x'));
    expect(resp.headers.get('X-Frame-Options')).toBe('DENY');
    expect(resp.headers.get('Content-Security-Policy')).toContain("script-src 'none'");
  });

  it('promotes an X-CSP-Nonce header into the CSP and strips it', () => {
    const resp = withSecurityHeaders(new Response('x', { headers: { 'X-CSP-Nonce': 'tok123' } }));
    expect(resp.headers.get('Content-Security-Policy')).toContain("script-src 'nonce-tok123'");
    expect(resp.headers.get('X-CSP-Nonce')).toBeNull();
  });
});

describe('hashIP', () => {
  const env = { IP_HASH_SECRET: 'unit-test-secret' };

  it('is deterministic and returns 16 lowercase hex chars', async () => {
    const a = await hashIP('203.0.113.7', env);
    const b = await hashIP('203.0.113.7', env);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  it('produces different hashes for different IPs', async () => {
    const a = await hashIP('203.0.113.7', env);
    const b = await hashIP('198.51.100.2', env);
    expect(a).not.toBe(b);
  });

  it('produces different hashes under different secrets (not a fixed public salt)', async () => {
    const a = await hashIP('203.0.113.7', { IP_HASH_SECRET: 'secret-one' });
    const b = await hashIP('203.0.113.7', { IP_HASH_SECRET: 'secret-two' });
    expect(a).not.toBe(b);
  });
});

describe('shardKeyFromIP', () => {
  it('is deterministic and within the shard range', () => {
    const k = shardKeyFromIP('abcdef0123456789');
    expect(k).toBe(shardKeyFromIP('abcdef0123456789'));
    expect(k).toMatch(/^shard-(\d|1[0-5])$/);
  });

  it('spreads different inputs across shards', () => {
    const shards = new Set();
    for (let i = 0; i < 64; i++) {
      shards.add(shardKeyFromIP('ip-' + i));
    }
    // Should not collapse everything onto a single shard.
    expect(shards.size).toBeGreaterThan(1);
  });
});
