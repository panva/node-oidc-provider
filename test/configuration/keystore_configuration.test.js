/* eslint-disable no-new */

const jose = require('@panva/jose');
const { expect } = require('chai');

const Provider = require('../../lib');

describe('configuration.jwks', () => {
  beforeEach(function () {
    this.keystore = new jose.JWKS.KeyStore();
  });

  it('must be a valid JWKS object', async function () {
    expect(() => {
      new Provider('http://localhost', {
        jwks: [],
      });
    }).to.throw('keystore must be a JSON Web Key Set formatted object');

    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));
    return new Provider('http://localhost', { jwks: this.keystore.toJWKS(true) });
  });

  it('must only contain EC and RS keys', async function () {
    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));
    await this.keystore.generate('oct', 256);

    expect(() => {
      new Provider('http://localhost', { jwks: this.keystore.toJWKS(true) });
    }).to.throw('only private RSA, EC or OKP keys should be part of keystore configuration');
  });

  it('must only contain private keys', async function () {
    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));

    expect(() => {
      new Provider('http://localhost', { jwks: { keys: [this.keystore.get().toJWK()] } });
    }).to.throw('only private RSA, EC or OKP keys should be part of keystore configuration');
  });

  it('allows to instantiate without RS256 if ID Tokens only come from the token_endpoint', function () {
    new Provider('http://localhost', {
      responseTypes: [
        'code',
        'none',
        'code token',
        'token',
      ],
      whitelistedJWA: {
        idTokenSigningAlgValues: ['none'],
      },
      jwks: this.keystore.toJWKS(true),
    });
  });
});
