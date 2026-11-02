import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hash } from 'node:crypto';

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
  ((actual) => { assert.throws(actual, (error) => { assert.ok('error' in Object(error)); assert.equal(error.error, 'invalid_grant'); return true; }); })(operation);
}

describe('security helper properties', () => {
  it('constantEquals agrees with string equality for Unicode input', { timeout: 3000 }, () => {
    fc.assert(
      fc.property(
        unicodeStrings,
        unicodeStrings,
        fc.integer({ min: 0, max: 1024 }),
        (left, right, minComp) => {
          assert.equal(constantEquals(left, right, minComp), left === right);
          assert.equal(constantEquals(left, right, minComp), constantEquals(right, left, minComp));
        },
      ),
      options,
    );
  });

  it('accepts valid S256 PKCE pairs and rejects mutations', { timeout: 3000 }, () => {
    fc.assert(
      fc.property(codeVerifiers, fc.nat(), (verifier, position) => {
        const challenge = hash('sha256', verifier, 'base64url');

        assert.doesNotThrow(() => checkPKCE(verifier, challenge, 'S256'));
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

  it('escapes arbitrary text for HTML contexts', { timeout: 3000 }, () => {
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

        assert.equal(output, expected);
        assert.doesNotMatch(output, /[<>"']/);
      }),
      options,
    );
  });
});
