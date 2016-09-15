'use strict';

const { Provider, createKeyStore, asKeyStore } = require('../../lib');
const { expect } = require('chai');

describe('configuration.tokenIntegrity', () => {
  it('must be provided a jose.JWK.KeyStore', function () {
    expect(function () {
      new Provider('http://localhost', { // eslint-disable-line no-new
        tokenIntegrity: true
      });
    }).to.throw('tokenIntegrity must be a jose.JWK.KeyStore instance');
  });

  it('works with the exported.createKeyStore fn', function () {
    return new Provider('http://localhost', {
      tokenIntegrity: createKeyStore()
    });
  });

  it('works with the exported.asKeyStore fn', function () {
    return asKeyStore({ keys: [] }).then((keystore) => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        tokenIntegrity: keystore
      });
    });
  });
});
