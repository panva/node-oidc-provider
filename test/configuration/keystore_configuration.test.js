'use strict';
/* eslint-disable no-new */

const jose = require('node-jose');
const { expect } = require('chai');
const { Provider } = require('../../lib');

const keystore = jose.JWK.createKeyStore();

describe('configuration.keystore', () => {
  it('be jwk keystore instance', function () {
    expect(function () {
      new Provider('http://localhost', { keystore: [] });
    }).to.throw('config.keystore must be a jose.JWK.KeyStore instance');
  });

  it('must contain at least RS256 signing key', function () {
    expect(function () {
      new Provider('http://localhost', { keystore });
    }).to.throw('RS256 signing must be supported but no viable key is found');

    return keystore.generate('RSA', 256).then(() => {
      new Provider('http://localhost', { keystore });
    });
  });

  it('must only contain EC and RS keys', function () {
    return keystore.generate('oct', 256).then(() => {
      expect(function () {
        new Provider('http://localhost', { keystore });
      }).to.throw('only private RSA or EC keys should be part of config.keystore');
    });
  });
});
