'use strict';

// MONGODB_URI=mongodb://localhost:27017/test node example/adapters/mongodb_test.js

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
  provider.initialize()
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
