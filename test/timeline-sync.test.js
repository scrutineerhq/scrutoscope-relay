import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

/**
 * The timeline renderer is a SHARED file: src/scrutinizer-timeline.js here must
 * stay BYTE-IDENTICAL to the plugin's assets/js/scrutinizer-timeline.js, so the
 * relay viewer and the WordPress dashboard render profiles the same way.
 *
 * When you change the timeline:
 *   1. Edit the canonical file and copy it to BOTH repos (identical bytes).
 *   2. Update EXPECTED_SHA256 below AND the matching constant in the plugin's
 *      tests/TimelineSyncTest.php to the new hash (they must be equal).
 *
 * If this test fails, the two copies have drifted — re-sync them.
 */
const EXPECTED_SHA256 = '1b21004b8af44171ba835daa98cb6f63a68ae983cca2a56c7bf715f9fc18114d';

describe('shared timeline renderer', () => {
  it('matches the byte-identical hash shared with the plugin', () => {
    const src = readFileSync(new URL('../src/scrutinizer-timeline.js', import.meta.url));
    const sha = createHash('sha256').update(src).digest('hex');
    expect(sha).toBe(EXPECTED_SHA256);
  });
});
