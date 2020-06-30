const { expect } = require('chai');

const set = require('../../lib/helpers/_/set');

describe('set', () => {
  it('sets properties by a dot notation', () => {
    const target = { a: 1, b: 2, c: { d: 3 } };
    set(
      target,
      'b.b2',
      2,
    );
    expect(
      target,
    ).to.eql(
      { a: 1, b: { b2: 2 }, c: { d: 3 } },
    );
    set(
      target,
      'c',
      3,
    );
    expect(
      target,
    ).to.eql(
      { a: 1, b: { b2: 2 }, c: 3 },
    );
    set(
      target,
      'd.e.f',
      4,
    );
    expect(
      target,
    ).to.eql(
      {
        a: 1, b: { b2: 2 }, c: 3, d: { e: { f: 4 } },
      },
    );
  });
});
