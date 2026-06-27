import { describe, it, expect } from 'vitest';
import { hashIP, shardKeyFromIP } from '../worker.js';

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
