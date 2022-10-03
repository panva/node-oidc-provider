/* eslint-disable no-new, no-console */

const jose = require('jose2');
const sinon = require('sinon').createSandbox();
const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('configuration.jwks', () => {
  beforeEach(function () {
    this.keystore = new jose.JWKS.KeyStore();
  });

  afterEach(sinon.restore);

  it('must be a valid JWKS object', async function () {
    expect(() => {
      new Provider('http://localhost', {
        jwks: [],
      });
    }).to.throw('keystore must be a JSON Web Key Set formatted object');

    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));
    return new Provider('http://localhost', { jwks: this.keystore.toJWKS(true) });
  });

  it('must only contain RSA, EC, or OKP keys', async function () {
    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));
    await this.keystore.generate('oct', 256);

    expect(() => {
      new Provider('http://localhost', { jwks: this.keystore.toJWKS(true) });
    }).to.throw('only RSA, EC, or OKP keys should be part of jwks configuration');
  });

  it('must only contain private keys', async function () {
    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));

    expect(() => {
      new Provider('http://localhost', { jwks: { keys: [this.keystore.get().toJWK()] } });
    }).to.throw('jwks.keys[0] configuration is missing required properties');
  });

  it('warns if "kid" is the same for multiple keys', async () => {
    const ks = new jose.JWKS.KeyStore();
    sinon.stub(console, 'warn').returns();
    await Promise.all([
      ks.generate('RSA', undefined, { kid: 'nov-2019' }),
      ks.generate('EC', undefined, { kid: 'nov-2019' }),
    ]);
    new Provider('http://localhost', {
      jwks: ks.toJWKS(true),
    });
    expect(console.warn.calledWithMatch(/different keys within the keystore SHOULD use distinct `kid` values, with your current keystore you should expect interoperability issues with your clients/)).to.be.true;
  });

  it('allows to instantiate without RS256 if ID Tokens only come from the token_endpoint', function () {
    new Provider('http://localhost', {
      responseTypes: [
        'code',
        'none',
        'code token',
      ],
      enabledJWA: {
        idTokenSigningAlgValues: ['none'],
      },
      jwks: this.keystore.toJWKS(true),
    });
  });

  it('supports secp256k1 keys', async () => {
    const ks = new jose.JWKS.KeyStore();
    await ks.generate('EC', 'secp256k1');

    expect(() => {
      new Provider('http://localhost', { jwks: ks.toJWKS(true) });
    }).not.to.throw();
  });
});
