const { strict: assert } = require('node:assert');
const crypto = require('node:crypto');

const { InvalidGrant } = require('./errors.js');
const checkFormat = require('./pkce_format.js');
const base64url = require('./base64url.js');

module.exports = function checkPKCE(verifier, challenge, method) {
  if (verifier) {
    checkFormat(verifier, 'code_verifier');
  }

  if (verifier || challenge) {
    try {
      let expected = verifier;
      assert(expected);

      if (method === 'S256') {
        expected = base64url.encodeBuffer(crypto.createHash('sha256').update(expected).digest());
      }

      assert.equal(challenge, expected);
    } catch (err) {
      throw new InvalidGrant('PKCE verification failed');
    }
  }
};
