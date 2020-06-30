const { expect } = require('chai');

const defaults = require('../../lib/helpers/_/defaults');

const { deep: defaultsDeep } = defaults;

describe('defaults', () => {
  it('fills default values in place of undefined', () => {
    const target = { a: 1, b: undefined };
    defaults(
      target,
      { a: 'x', b: 2, c: 3 },
      { c: 'x' },
    );
    expect(
      target,
    ).to.eql(
      { a: 1, b: 2, c: 3 },
    );
  });

  it('does nothing with nested objects', () => {
    expect(
      defaults(
        { a: { b: undefined } },
        { a: { b: 2, c: 'x' } },
      ),
    ).to.eql(
      { a: { b: undefined } },
    );
  });

  it('does nothing with non objects', () => {
    expect(
      defaults(
        { 0: 1 },
        [2],
      ),
    ).to.eql(
      { 0: 1 },
    );
  });
});

describe('defaultsDeep', () => {
  it('fills default values in place of undefined', () => {
    const target = { a: 1, b: undefined };
    defaultsDeep(
      target,
      { a: 'x', b: 2, c: 3 },
      { c: 'x' },
    );
    expect(
      target,
    ).to.eql(
      { a: 1, b: 2, c: 3 },
    );
  });

  it('also handles nested objects', () => {
    expect(
      defaultsDeep(
        { a: { b: undefined } },
        { a: { b: 2, c: 'x' } },
      ),
    ).to.eql(
      { a: { b: 2, c: 'x' } },
    );
  });
});
