const { expect } = require('chai');

const constantEquals = require('../../lib/helpers/constant_equals');

describe('constantEquals', () => {
  it('compares strings in equal time', () => {
    const a = 'abcdf';
    const b = 'abcdf';
    const c = 'abcde';
    const d = 'abcdef';

    expect(constantEquals(a, b)).to.be.true;
    expect(constantEquals(b, c)).to.be.false;
    expect(constantEquals(c, d)).to.be.false;
    expect(constantEquals(a, a)).to.be.true;
    expect(constantEquals('abc', 'a0c')).to.be.false;
    expect(() => constantEquals(Buffer.alloc(1), 'abc')).to.throw();
  });

  it('also works when providing minComp', () => {
    const a1 = 'abcde';
    const a2 = 'abcde';
    const b1 = 'abcdef';
    const c1 = 'abcdeg';

    expect(constantEquals(a1, a2, 0)).to.be.true;
    expect(constantEquals(a1, a2, a1.length)).to.be.true;
    expect(constantEquals(a1, a2, a1.length + 1)).to.be.true;

    expect(constantEquals(a1, b1, 0)).to.be.false;
    expect(constantEquals(a1, b1, a1.length)).to.be.false;
    expect(constantEquals(a1, b1, a1.length + 1)).to.be.false;

    expect(constantEquals(b1, c1, 0)).to.be.false;
    expect(constantEquals(b1, c1, b1.length - 1)).to.be.false;
    expect(constantEquals(b1, c1, b1.length)).to.be.false;
    expect(constantEquals(b1, c1, b1.length + 1)).to.be.false;
    expect(() => constantEquals(Buffer.alloc(1), c1, c1.length + 1)).to.throw();

    expect(constantEquals('foo', 'foo', 512)).to.be.true;
  });
});
