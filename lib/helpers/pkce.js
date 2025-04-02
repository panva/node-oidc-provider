import * as crypto from 'node:crypto';

import { InvalidGrant } from './errors.js';
import checkFormat from './pkce_format.js';
import constantEquals from './constant_equals.js';

export default function checkPKCE(verifier, challenge, method) {
  if (verifier) {
    checkFormat(verifier, 'code_verifier');
  }

  if (verifier || challenge) {
    try {
      let expected = verifier;
      if (!expected) throw new Error();

      if (method === 'S256') {
        expected = crypto.hash('sha256', expected, 'base64url');
      } else {
        throw new Error();
      }

      if (!constantEquals(challenge, expected)) {
        throw new Error();
      }
    } catch (err) {
      throw new InvalidGrant('PKCE verification failed');
    }
  }
}
