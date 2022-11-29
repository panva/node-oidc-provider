import { strict as assert } from 'node:assert';
import crypto from 'node:crypto';

import { InvalidGrant } from './errors.js';
import checkFormat from './pkce_format.js';
import * as base64url from './base64url.js';

export default function checkPKCE(verifier, challenge, method) {
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
}
