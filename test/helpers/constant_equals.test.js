import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import constantEquals from '../../lib/helpers/constant_equals.js';

describe('constantEquals', () => {
  it('compares strings in equal time', { timeout: 3000 }, () => {
    const a = 'abcdf';
    const b = 'abcdf';
    const c = 'abcde';
    const d = 'abcdef';

    assert.equal(constantEquals(a, b), true);
    assert.equal(constantEquals(b, c), false);
    assert.equal(constantEquals(c, d), false);
    assert.equal(constantEquals(a, a), true);
    assert.equal(constantEquals('abc', 'a0c'), false);
    assert.equal(constantEquals('éa', 'éb'), false);
    assert.throws(() => constantEquals(Buffer.alloc(1), 'abc'));
  });

  it('also works when providing minComp', { timeout: 3000 }, () => {
    const a1 = 'abcde';
    const a2 = 'abcde';
    const b1 = 'abcdef';
    const c1 = 'abcdeg';

    assert.equal(constantEquals(a1, a2, 0), true);
    assert.equal(constantEquals(a1, a2, a1.length), true);
    assert.equal(constantEquals(a1, a2, a1.length + 1), true);

    assert.equal(constantEquals(a1, b1, 0), false);
    assert.equal(constantEquals(a1, b1, a1.length), false);
    assert.equal(constantEquals(a1, b1, a1.length + 1), false);

    assert.equal(constantEquals(b1, c1, 0), false);
    assert.equal(constantEquals(b1, c1, b1.length - 1), false);
    assert.equal(constantEquals(b1, c1, b1.length), false);
    assert.equal(constantEquals(b1, c1, b1.length + 1), false);
    assert.throws(() => constantEquals(Buffer.alloc(1), c1, c1.length + 1));

    assert.equal(constantEquals('foo', 'foo', 512), true);
  });
});
