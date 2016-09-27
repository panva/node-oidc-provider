'use strict';

/* eslint-disable no-console */

const oidc = require('../../lib');
const MongoAdapter = require('./mongodb');

const Provider = oidc.Provider;
const AdapterTest = oidc.AdapterTest;

const provider = new Provider('http://localhost', {
  adapter: MongoAdapter,
});
const test = new AdapterTest(provider);

MongoAdapter.once('ready', () => {
  provider.keystore.generate('RSA', 512)
  .then(() => test.execute())
  .then(() => {
    console.log('tests passed');
    process.exit();
  })
  .catch((err) => {
    console.dir(err);
    process.exit(1);
  });
});
