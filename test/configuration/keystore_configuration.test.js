/* eslint-disable no-new, no-console */

import { randomBytes } from 'node:crypto';

import { generateKeyPair } from 'jose';
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
    }).to.throw('only RSA, EC, or OKP keys should be part of jwks configuration');
  });

  it('must only contain private keys', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');

    expect(() => {
      new Provider('http://localhost', { jwks: { keys: [publicKey.export({ format: 'jwk' })] } });
    }).to.throw('jwks.keys[0] configuration is missing required properties');
  });

  it('warns if "kid" is the same for multiple keys', async () => {
    sinon.stub(console, 'warn').returns();
    const [rsa, ec] = await Promise.all([
      generateKeyPair('RS256'),
      generateKeyPair('ES256'),
    ]);
    new Provider('http://localhost', {
      jwks: {
        keys: [
          { ...rsa.privateKey.export({ format: 'jwk' }), kid: 'nov-2019' },
          { ...ec.privateKey.export({ format: 'jwk' }), kid: 'nov-2019' },
        ],
      },
    });
    expect(console.warn.calledWithMatch(/different keys within the keystore SHOULD use distinct `kid` values, with your current keystore you should expect interoperability issues with your clients/)).to.be.true;
  });

  it('supports secp256k1 keys', async () => {
    const { privateKey } = await generateKeyPair('ES256K');

    expect(() => {
      new Provider('http://localhost', { jwks: { keys: [privateKey.export({ format: 'jwk' })] } });
    }).not.to.throw();
  });
});
