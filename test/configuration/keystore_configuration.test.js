/* eslint-disable no-new, no-console */

import { randomBytes } from 'node:crypto';

import { generateKeyPair, exportJWK } from 'jose';
import { createSandbox } from 'sinon';
import { expect } from 'chai';

import Provider from '../../lib/index.js';

const sinon = createSandbox();

describe('configuration.jwks', () => {
  afterEach(sinon.restore);

  it('must be a valid JWKS object', async () => {
    expect(() => {
      new Provider('http://localhost', {
        jwks: [],
      });
    }).to.throw('keystore must be a JSON Web Key Set formatted object');
  });

  it('must only contain RSA, EC, or OKP keys', () => {
    expect(() => {
      new Provider('http://localhost', {
        jwks: {
          keys: [
            { kty: 'oct', k: randomBytes(32).toString('base64url') },
          ],
        },
      });
    }).to.throw('only RSA, EC, OKP, or AKP keys should be part of jwks configuration');
  });

  it('must only contain private keys', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const jwks = { keys: [await exportJWK(publicKey)] };

    expect(() => {
      new Provider('http://localhost', { jwks });
    }).to.throw('jwks.keys[0].d configuration must be a non-empty string');
  });

  it('must only contain private keys (ML-DSA)', async function () {
    if (SubtleCrypto.supports?.('generateKey', 'ML-DSA-44') !== true) {
      this.skip();
    }
    const { publicKey } = await generateKeyPair('ML-DSA-44');
    const jwks = { keys: [await exportJWK(publicKey)] };

    expect(() => {
      new Provider('http://localhost', { jwks });
    }).to.throw('jwks.keys[0].priv configuration must be a non-empty string');
  });

  it('rejects if "kid" is the same for multiple keys', async () => {
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

    expect(() => {
      new Provider('http://localhost', config);
    }).to.throw('jwks.keys configuration must not contain duplicate "kid" values');
  });
});
