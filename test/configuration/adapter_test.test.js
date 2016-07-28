'use strict';

const oidc = require('../../lib');
const { TestAdapter } = require('../models');

const Provider = oidc.Provider;
const AdapterTest = oidc.AdapterTest;


describe('AdapterTest', function () {
  it('passes with the default MemoryAdapter', function () {
    const provider = new Provider('http://localhost');
    const test = new AdapterTest(provider);

    return provider.keystore.generate('RSA', 512)
    .then(() => test.execute());
  });

  it('passes with the TestAdapter', function () {
    const provider = new Provider('http://localhost', {
      adapter: TestAdapter
    });
    const test = new AdapterTest(provider);

    return provider.keystore.generate('RSA', 512)
      .then(() => test.execute());
  });
});
