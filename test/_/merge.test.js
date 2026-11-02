import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import merge from '../../lib/helpers/_/merge.js';

describe('merge', () => {
  it('merges objects', { timeout: 3000 }, () => {
    const target = { a: 1, b: 2, c: { d: 3 } };
    merge(
      target,
      { a: 'x', b: { b: 2 }, c: { e: 4 } },
      { c: { f: 5 } },
    );
    assert.deepEqual(target, { a: 'x', b: { b: 2 }, c: { d: 3, e: 4, f: 5 } });
  });
});
