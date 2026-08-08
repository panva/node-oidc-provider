import { expect } from 'chai';
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
        expect(mine.get(key), `get(${key})`).to.deep.equal(theirs.get(key));
        expect(mine.has(key), `has(${key})`).to.equal(theirs.has(key));
      }
      expect(mine.size, 'size').to.equal(theirs.size);
    },
    delete(key) {
      expect(mine.delete(key), `delete(${key})`).to.equal(theirs.delete(key));
    },
    get(key) {
      const a = mine.get(key);
      const b = theirs.get(key);
      expect(a).to.deep.equal(b);
      return a;
    },
  };
};

describe('lru transcription', () => {
  it('rejects a missing or zero maxSize, as quick-lru does', () => {
    for (const options of [{}, { maxSize: 0 }, { maxSize: -1 }]) {
      expect(() => new LRU(options)).to.throw(TypeError, '`maxSize` must be a number greater than 0');
      expect(() => new QuickLRU(options)).to.throw(TypeError);
    }
  });

  it('agrees across the eviction boundary', () => {
    const maxSize = 10;
    const lru = mirror(maxSize);
    const keys = Array.from({ length: 40 }, (_, i) => `k${i}`);

    for (const [i, key] of keys.entries()) {
      lru.set(key, { i });
      lru.check(keys);
    }
  });

  it('agrees when reads promote stale entries', () => {
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

  it('agrees on overwrites', () => {
    const lru = mirror(5);
    const keys = ['a', 'b', 'c'];
    lru.set('a', 1);
    lru.set('a', 2);
    lru.set('b', 1);
    lru.check(keys);
    lru.set('a', 3);
    lru.check(keys);
  });

  it('agrees on delete of present, absent and stale keys', () => {
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

  it('agrees on per entry expiry', async () => {
    const lru = mirror(10);
    lru.set('fresh', 1, { maxAge: 60_000 });
    lru.set('brief', 2, { maxAge: 15 });
    lru.set('forever', 3);
    lru.check(['fresh', 'brief', 'forever']);

    await new Promise((resolve) => { setTimeout(resolve, 40); });

    expect(lru.get('brief')).to.equal(undefined);
    lru.check(['fresh', 'brief', 'forever']);
  });

  it('agrees on expiry of entries that fell into the stale generation', async () => {
    const lru = mirror(3);
    lru.set('a', 1, { maxAge: 15 });
    lru.set('b', 2);
    lru.set('c', 3);
    lru.set('d', 4);

    await new Promise((resolve) => { setTimeout(resolve, 40); });

    expect(lru.get('a')).to.equal(undefined);
    lru.check(['a', 'b', 'c', 'd']);
  });

  it('agrees over a randomised operation sequence', () => {
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
