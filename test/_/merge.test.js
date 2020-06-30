const { expect } = require('chai');

const merge = require('../../lib/helpers/_/merge');

describe('merge', () => {
  it('merges objects', () => {
    const target = { a: 1, b: 2, c: { d: 3 } };
    merge(
      target,
      { a: 'x', b: { b: 2 }, c: { e: 4 } },
      { c: { f: 5 } },
    );
    expect(
      target,
    ).to.eql(
      { a: 'x', b: { b: 2 }, c: { d: 3, e: 4, f: 5 } },
    );
  });
});
