import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import defaults, { deep } from '../../lib/helpers/_/defaults.js';

describe('defaults', () => {
  it('fills default values in place of undefined', { timeout: 3000 }, () => {
    const target = { a: 1, b: undefined };
    defaults(
      target,
      { a: 'x', b: 2, c: 3 },
      { c: 'x' },
    );
    assert.deepEqual(target, { a: 1, b: 2, c: 3 });
  });

  it('does nothing with nested objects', { timeout: 3000 }, () => {
    assert.deepEqual(defaults(
        { a: { b: undefined } },
        { a: { b: 2, c: 'x' } },
      ), { a: { b: undefined } });
  });

  it('does nothing with non objects', { timeout: 3000 }, () => {
    assert.deepEqual(defaults(
        { 0: 1 },
        [2],
      ), { 0: 1 });
  });
});

describe('defaultsDeep', () => {
  it('fills default values in place of undefined', { timeout: 3000 }, () => {
    const target = { a: 1, b: undefined };
    deep(
      target,
      { a: 'x', b: 2, c: 3 },
      { c: 'x' },
    );
    assert.deepEqual(target, { a: 1, b: 2, c: 3 });
  });

  it('also handles nested objects', { timeout: 3000 }, () => {
    assert.deepEqual(deep(
        { a: { b: undefined } },
        { a: { b: 2, c: 'x' } },
      ), { a: { b: 2, c: 'x' } });
  });
});
