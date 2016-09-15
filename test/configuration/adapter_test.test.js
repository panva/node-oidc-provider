'use strict';

const oidc = require('../../lib');
const { TestAdapter } = require('../models');
const jose = require('node-jose');

const Provider = oidc.Provider;
const AdapterTest = oidc.AdapterTest;


describe('AdapterTest', () => {
  const integrity = (!process.env.INTEGRITY && Math.floor(Math.random() * 2)) ||
    process.env.INTEGRITY === 'true';

  if (integrity) {
    before(function () {
      const ks = jose.JWK.createKeyStore();
      this.ks = ks;
      return ks.generate('oct', 512, { alg: 'HS512' });
    });
  }

  it('passes with the default MemoryAdapter', function () {
    const provider = new Provider('http://localhost', {
      tokenIntegrity: this.ks
    });
    const test = new AdapterTest(provider);

    return provider.keystore.generate('RSA', 512)
    .then(() => test.execute());
  });

  it('passes with the TestAdapter', function () {
    const provider = new Provider('http://localhost', {
      adapter: TestAdapter,
      tokenIntegrity: this.ks
    });
    const test = new AdapterTest(provider);

    return provider.keystore.generate('RSA', 512)
      .then(() => test.execute());
  });
});
