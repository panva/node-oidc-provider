/* eslint-disable no-new */

const jose = require('node-jose');
const { expect } = require('chai');

const Provider = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('configuration.keystore', () => {
  beforeEach(function () {
    this.keystore = jose.JWK.createKeyStore();
  });

  it('must contain at least one RS256 signing key', async function () {
    const provider = new Provider('http://localhost');

    await provider.initialize({ keystore: this.keystore }).then(fail, (err) => {
      expect(err.message).to.equal('RS256 signing must be supported but no viable key was provided');
    });
    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));
    await provider.initialize({ keystore: this.keystore });
  });

  it('must only contain EC and RS keys', async function () {
    const provider = new Provider('http://localhost');
    await this.keystore.add(global.keystore.get({ kty: 'RSA' }));

    return this.keystore.generate('oct', 256)
      .then(() => provider.initialize({ keystore: this.keystore }))
      .then(fail, (err) => {
        expect(err.message).to.equal('only private RSA or EC keys should be part of keystore configuration');
      });
  });

  it('allows to initialize without RS256 if ID Tokens only come from the token_endpoint', function () {
    const provider = new Provider('http://localhost', {
      responseTypes: [
        'code',
        'none',
        'code token',
        'token',
      ],
      whitelistedJWA: {
        idTokenSigningAlgValues: ['none'],
      },
    });

    return provider.initialize({ keystore: this.keystore });
  });
});
