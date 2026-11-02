import { describe, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { generateKeyPair, exportJWK } from 'jose';
import { createSandbox } from 'sinon';

import Provider from '../../lib/index.js';

const sinon = createSandbox();

describe('configuration.jwks', () => {

  afterEach(() => sinon.restore(), { timeout: 3000 });

  it('must be a valid JWKS object', { timeout: 3000 }, async () => {
    const jwks = [];
    let caught;
    try {
      new Provider('http://localhost', {
        jwks,
      });
    } catch (err) {
      caught = err;
    }

    ((actual) => { assert.ok(actual instanceof Error); assert.ok('message' in Object(actual)); assert.equal(actual.message, 'keystore must be a JSON Web Key Set formatted object'); })(caught);
    assert.deepEqual(caught.cause, jwks);
  });

  it('must only contain RSA, EC, or OKP keys', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('http://localhost', {
        jwks: {
          keys: [
            { kty: 'oct', k: randomBytes(32).toString('base64url') },
          ],
        },
      });
    }, (error) => { assert.ok(error.message.includes('only RSA, EC, OKP, or AKP keys should be part of jwks configuration')); return true; });
  });

  it('must only contain private keys', { timeout: 3000 }, async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const jwks = { keys: [await exportJWK(publicKey)] };

    assert.throws(() => {
      new Provider('http://localhost', { jwks });
    }, (error) => { assert.ok(error.message.includes('jwks.keys[0].d configuration must be a non-empty string')); return true; });
  });

  it('must only contain private keys (ML-DSA)', { timeout: 3000 }, async (t) => {
    if (SubtleCrypto.supports?.('generateKey', 'ML-DSA-44') !== true) {
      return t.skip();
    }
    const { publicKey } = await generateKeyPair('ML-DSA-44');
    const jwks = { keys: [await exportJWK(publicKey)] };

    assert.throws(() => {
      new Provider('http://localhost', { jwks });
    }, (error) => { assert.ok(error.message.includes('jwks.keys[0].priv configuration must be a non-empty string')); return true; });
  });

  it('rejects if "kid" is the same for multiple keys', { timeout: 3000 }, async () => {
    const [rsa, ec] = await Promise.all([
      generateKeyPair('RS256', { extractable: true }),
      generateKeyPair('ES256', { extractable: true }),
    ]);
    const config = {
      jwks: {
        keys: [
          { ...await exportJWK(rsa.privateKey), kid: 'nov-2019' },
          { ...await exportJWK(ec.privateKey), kid: 'nov-2019' },
        ],
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config);
    }, (error) => { assert.ok(error.message.includes('jwks.keys configuration must not contain duplicate "kid" values')); return true; });
  });
});
