'use strict';

/* eslint-disable no-new */

const jose = require('node-jose');
const { expect } = require('chai');
const { Provider } = require('../../lib');

const keystore = jose.JWK.createKeyStore();
const fail = () => { throw new Error('expected promise to be rejected'); };

describe('configuration.keystore', function () {
  it('must contain at least one RS256 signing key', function () {
    const provider = new Provider('http://localhost');

    return provider.initialize({ keystore }).then(fail, function (err) {
      expect(err.message).to.equal('RS256 signing must be supported but no viable key was provided');
    }).then(function () {
      return keystore.generate('RSA', 256);
    }).then(function () {
      provider.initialize({ keystore });
    });
  });

  it('must only contain EC and RS keys', function () {
    const provider = new Provider('http://localhost');

    return keystore.generate('oct', 256)
      .then(() => provider.initialize({ keystore }))
      .then(fail, function (err) {
        expect(err.message).to.equal('only private RSA or EC keys should be part of keystore configuration');
      });
  });
});
