import { hash } from 'node:crypto';

import { expect } from 'chai';
import fc from 'fast-check';

import constantEquals from '../../lib/helpers/constant_equals.js';
import htmlSafe from '../../lib/helpers/html_safe.js';
import checkPKCE from '../../lib/helpers/pkce.js';

const options = { numRuns: 100 };
const unicodeStrings = fc.string({ unit: 'grapheme', maxLength: 512 });
const pkceCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
const codeVerifiers = fc
  .array(fc.constantFrom(...pkceCharacters), { minLength: 43, maxLength: 128 })
  .map((characters) => characters.join(''));

function mutate(value, position) {
  const offset = position % value.length;
  const current = pkceCharacters.indexOf(value[offset]);
  const replacement = pkceCharacters[(current + 1) % pkceCharacters.length];

  return `${value.slice(0, offset)}${replacement}${value.slice(offset + 1)}`;
}

function expectInvalidGrant(operation) {
  expect(operation).to.throw().with.property('error', 'invalid_grant');
}

describe('security helper properties', () => {
  it('constantEquals agrees with string equality for Unicode input', () => {
    fc.assert(
      fc.property(
        unicodeStrings,
        unicodeStrings,
        fc.integer({ min: 0, max: 1024 }),
        (left, right, minComp) => {
          expect(constantEquals(left, right, minComp)).to.equal(left === right);
          expect(constantEquals(left, right, minComp)).to.equal(
            constantEquals(right, left, minComp),
          );
        },
      ),
      options,
    );
  });

  it('accepts valid S256 PKCE pairs and rejects mutations', () => {
    fc.assert(
      fc.property(codeVerifiers, fc.nat(), (verifier, position) => {
        const challenge = hash('sha256', verifier, 'base64url');

        expect(() => checkPKCE(verifier, challenge, 'S256')).not.to.throw();
        expectInvalidGrant(
          () => checkPKCE(mutate(verifier, position), challenge, 'S256'),
        );
        expectInvalidGrant(
          () => checkPKCE(verifier, mutate(challenge, position), 'S256'),
        );
      }),
      options,
    );
  });

  it('escapes arbitrary text for HTML contexts', () => {
    const entities = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    };

    fc.assert(
      fc.property(unicodeStrings, (input) => {
        const expected = [...input]
          .map((character) => entities[character] ?? character)
          .join('');
        const output = htmlSafe(input);

        expect(output).to.equal(expected);
        expect(output).not.to.match(/[<>"']/);
      }),
      options,
    );
  });
});
