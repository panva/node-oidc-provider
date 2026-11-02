import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import set from '../../lib/helpers/_/set.js';

describe('set', () => {
  it('sets properties by a dot notation', { timeout: 3000 }, () => {
    const target = { a: 1, b: 2, c: { d: 3 } };
    set(
      target,
      'b.b2',
      2,
    );
    assert.deepEqual(target, { a: 1, b: { b2: 2 }, c: { d: 3 } });
    set(
      target,
      'c',
      3,
    );
    assert.deepEqual(target, { a: 1, b: { b2: 2 }, c: 3 });
    set(
      target,
      'd.e.f',
      4,
    );
    assert.deepEqual(target, {
        a: 1, b: { b2: 2 }, c: 3, d: { e: { f: 4 } },
      });
  });
});
