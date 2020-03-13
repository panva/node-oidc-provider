const { strict: assert } = require('assert');
const crypto = require('crypto');

const { InvalidGrant } = require('./errors');
const checkFormat = require('./pkce_format');
const base64url = require('./base64url');

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
