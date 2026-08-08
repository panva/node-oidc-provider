import { customAlphabet as theirs, urlAlphabet as theirAlphabet } from 'nanoid';
import { expect } from 'chai';

import nanoid, { customAlphabet as mine, urlAlphabet } from '../../lib/helpers/nanoid.js';

/*
 * lib/helpers/nanoid.js is a transcription of nanoid's customAlphabet. These
 * values are bearer tokens, session ids and device flow user codes, so what has
 * to hold is the alphabet, the length, and a uniform distribution. nanoid is
 * kept as a devDependency to hold the transcription to it.
 */

const ALPHABETS = {
  url: urlAlphabet, // 64, a power of two - masking only, nothing rejected
  'base-20': 'BCDFGHJKLMNPQRSTVWXZ', // device flow
  digits: '0123456789', // device flow
};

const distribution = (generate, alphabet, total) => {
  const counts = new Map([...alphabet].map((char) => [char, 0]));
  let produced = 0;
  while (produced < total) {
    for (const char of generate(100)) {
      counts.set(char, counts.get(char) + 1);
      produced += 1;
    }
  }
  const expected = produced / alphabet.length;
  let chiSquare = 0;
  for (const observed of counts.values()) chiSquare += ((observed - expected) ** 2) / expected;
  return chiSquare;
};

describe('nanoid transcription', () => {
  it('uses the same url alphabet', () => {
    expect(urlAlphabet).to.equal(theirAlphabet);
    expect(urlAlphabet).to.have.lengthOf(64);
  });

  it('produces the same default id length', () => {
    expect(nanoid()).to.have.lengthOf(43);
    expect(nanoid()).to.have.lengthOf(theirs(theirAlphabet, 43)().length);
  });

  it('returns an empty string for size 0, as nanoid does', () => {
    expect(mine(urlAlphabet, 43)(0)).to.equal('');
    expect(theirs(urlAlphabet, 43)(0)).to.equal('');
  });

  it('coerces and rejects sizes the way nanoid does', () => {
    // formats.bitsOfOpaqueRandomness is configurable and feeds this; a negative
    // size must throw rather than yield an empty token value
    const ours = mine(urlAlphabet, 43);
    const nanoids = theirs(urlAlphabet, 43);

    for (const size of [-1000, -1, 0, 1, 1.5, 42.9, NaN, Infinity, '10', undefined]) {
      const run = (fn) => {
        try { return `len ${fn(size).length}`; } catch (err) { return `throws ${err.constructor.name}`; }
      };
      expect(run(ours), `size ${String(size)}`).to.equal(run(nanoids));
    }

    expect(() => ours(-1)).to.throw(RangeError, 'Wrong ID size');
  });

  it('spans the pool correctly for ids larger than it', () => {
    for (const size of [4095, 4096, 4097, 8192, 10_000]) {
      const id = mine(urlAlphabet)(size);
      expect(id).to.have.lengthOf(size);
      for (const char of id) expect(urlAlphabet).to.include(char);
    }
  });

  it('refuses an alphabet it cannot represent', () => {
    expect(() => mine('✓✗', 4)).to.throw(TypeError, 'alphabet must be latin1');
  });

  for (const [name, alphabet] of Object.entries(ALPHABETS)) {
    it(`${name}: emits only alphabet characters at the requested length`, () => {
      for (const size of [1, 2, 3, 6, 8, 9, 10, 21, 43, 64, 128]) {
        const generate = mine(alphabet, size);
        for (let i = 0; i < 200; i += 1) {
          const id = generate();
          expect(id).to.have.lengthOf(size);
          for (const char of id) expect(alphabet).to.include(char);
        }
      }
    });

    it(`${name}: is as uniformly distributed as nanoid`, () => {
      const ours = distribution(mine(alphabet), alphabet, 200_000);
      const nanoids = distribution(theirs(alphabet), alphabet, 200_000);

      // 63 degrees of freedom has a 0.1% critical value around 148; the bound
      // below sits above that but far under what a modulo bias would produce,
      // which lands in the thousands.
      const bound = alphabet.length * 4;
      expect(ours, `chi-square ${ours.toFixed(1)} vs nanoid ${nanoids.toFixed(1)}`).to.be.below(bound);
      expect(nanoids).to.be.below(bound);
    });

    // only meaningful where the alphabet does not fill the mask exactly; a
    // power-of-two alphabet has nothing to reject in the first place
    const fillsMask = (2 << (31 - Math.clz32((alphabet.length - 1) | 1))) - 1 === alphabet.length - 1;
    (fillsMask ? it.skip : it)(`${name}: rejects out-of-range values rather than folding them`, () => {
      // 20 symbols under a 31 mask: folding 20..31 back with % would make the
      // first 12 symbols appear twice as often as the last 8, a ratio of 2.
      const generate = mine(alphabet, 1);
      const counts = new Map([...alphabet].map((char) => [char, 0]));
      for (let i = 0; i < 200_000; i += 1) {
        const char = generate();
        counts.set(char, counts.get(char) + 1);
      }
      const values = [...counts.values()];
      expect(Math.max(...values) / Math.min(...values)).to.be.below(1.25);
    });
  }
});
