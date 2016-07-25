/* eslint-disable no-console */
'use strict';

const oidc = require('../../lib');
const RedisAdapter = require('./redis');

const Provider = oidc.Provider;
const AdapterTest = oidc.AdapterTest;

const provider = new Provider('http://localhost', {
  adapter: RedisAdapter,
});
const test = new AdapterTest(provider);

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
