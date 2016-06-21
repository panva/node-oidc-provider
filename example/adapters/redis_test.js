/* eslint-disable no-console */
'use strict';

const Provider = require('../../lib').Provider;

const RedisAdapter = require('./redis');
const AdapterTest = require('./adapter_test');

const accountId = require('node-uuid').v4;
const clientId = require('node-uuid').v4;

const provider = new Provider('http://localhost', {
  adapter: RedisAdapter,
  pairwiseSalt: 'random',
});

provider.keystore.generate('RSA', 512).then(() => {
  const test = new AdapterTest(provider, accountId, clientId);
  test.run();
}).catch(console.dir);
