const assert = require('assert');
const crypto = require('crypto');

const base64url = require('base64url');

const { InvalidGrant } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

module.exports = provider => function checkPKCE(verifier, challenge, method) {
  const pkce = instance(provider).configuration('features.pkce');
  if (pkce && (verifier || challenge)) {
    try {
      let expected = verifier;
      assert(expected);

      if (method === 'S256') {
        expected = base64url(crypto.createHash('sha256').update(expected).digest());
      }

      assert.deepEqual(challenge, expected);
    } catch (err) {
      throw new InvalidGrant('PKCE verification failed');
    }
  }
};
