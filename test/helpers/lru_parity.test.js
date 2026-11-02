import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import QuickLRU from 'quick-lru';

import LRU from '../../lib/helpers/lru.js';

/*
 * lib/helpers/lru.js is a transcription of the quick-lru surface oidc-provider
 * uses. quick-lru is kept as a devDependency so the transcription can be held
 * to it: the same operation sequence must produce the same observable state,
 * including the generational eviction boundary and lazy per entry expiry.
 *
 * The memory adapter depends on maxAge for token expiry, so that is the part
 * that has to be right.
 */

const mirror = (maxSize) => {
  const mine = new LRU({ maxSize });
  const theirs = new QuickLRU({ maxSize });
  return {
    set(key, value, options) {
      mine.set(key, value, options);
      theirs.set(key, value, options);
    },
    check(keys) {
      for (const key of keys) {
        assert.deepEqual(mine.get(key), theirs.get(key), `get(${key})`);
        assert.equal(mine.has(key), theirs.has(key), `has(${key})`);
      }
      assert.equal(mine.size, theirs.size, 'size');
    },
    delete(key) {
      assert.equal(mine.delete(key), theirs.delete(key), `delete(${key})`);
    },
    get(key) {
      const a = mine.get(key);
      const b = theirs.get(key);
      assert.deepEqual(a, b);
      return a;
    },
  };
};

describe('lru transcription', () => {
  it('rejects a missing or zero maxSize, as quick-lru does', { timeout: 3000 }, () => {
    for (const options of [{}, { maxSize: 0 }, { maxSize: -1 }]) {
      assert.throws(() => new LRU(options), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('`maxSize` must be a number greater than 0')); return true; });
      assert.throws(() => new QuickLRU(options), (error) => { assert.ok(error instanceof TypeError); return true; });
    }
  });

  it('agrees across the eviction boundary', { timeout: 3000 }, () => {
    const maxSize = 10;
    const lru = mirror(maxSize);
    const keys = Array.from({ length: 40 }, (_, i) => `k${i}`);

    for (const [i, key] of keys.entries()) {
      lru.set(key, { i });
      lru.check(keys);
    }
  });

  it('agrees when reads promote stale entries', { timeout: 3000 }, () => {
    const lru = mirror(4);
    const keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];

    lru.set('a', 1);
    lru.set('b', 2);
    lru.set('c', 3);
    lru.get('a'); // promote out of the stale generation
    lru.set('d', 4);
    lru.set('e', 5);
    lru.check(keys);
    lru.get('a');
    lru.set('f', 6);
    lru.check(keys);
    lru.delete('a');
    lru.check(keys);
  });

  it('agrees on overwrites', { timeout: 3000 }, () => {
    const lru = mirror(5);
    const keys = ['a', 'b', 'c'];
    lru.set('a', 1);
    lru.set('a', 2);
    lru.set('b', 1);
    lru.check(keys);
    lru.set('a', 3);
    lru.check(keys);
  });

  it('agrees on delete of present, absent and stale keys', { timeout: 3000 }, () => {
    const lru = mirror(3);
    lru.set('a', 1);
    lru.set('b', 2);
    lru.set('c', 3);
    lru.set('d', 4);
    lru.delete('a');
    lru.delete('a');
    lru.delete('zzz');
    lru.delete('d');
    lru.check(['a', 'b', 'c', 'd', 'zzz']);
  });

  it('agrees on per entry expiry', { timeout: 3000 }, async () => {
    const lru = mirror(10);
    lru.set('fresh', 1, { maxAge: 60_000 });
    lru.set('brief', 2, { maxAge: 15 });
    lru.set('forever', 3);
    lru.check(['fresh', 'brief', 'forever']);

    await new Promise((resolve) => { setTimeout(resolve, 40); });

    assert.equal(lru.get('brief'), undefined);
    lru.check(['fresh', 'brief', 'forever']);
  });

  it('agrees on expiry of entries that fell into the stale generation', { timeout: 3000 }, async () => {
    const lru = mirror(3);
    lru.set('a', 1, { maxAge: 15 });
    lru.set('b', 2);
    lru.set('c', 3);
    lru.set('d', 4);

    await new Promise((resolve) => { setTimeout(resolve, 40); });

    assert.equal(lru.get('a'), undefined);
    lru.check(['a', 'b', 'c', 'd']);
  });

  it('agrees over a randomised operation sequence', { timeout: 3000 }, () => {
    const maxSize = 8;
    const lru = mirror(maxSize);
    const keys = Array.from({ length: 20 }, (_, i) => `k${i}`);

    // deterministic PRNG so a failure is reproducible
    let seed = 42;
    const next = () => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed / 2147483648;
    };

    for (let i = 0; i < 5000; i += 1) {
      const key = keys[Math.floor(next() * keys.length)];
      const roll = next();
      if (roll < 0.55) {
        lru.set(key, { i }, next() < 0.3 ? { maxAge: 60_000 } : undefined);
      } else if (roll < 0.85) {
        lru.get(key);
      } else {
        lru.delete(key);
      }
    }

    lru.check(keys);
  });
});
