'use strict';

// node example/adapters/redis_test.js

/* eslint-disable no-console */

const Provider = require('../../lib');
const RedisAdapter = require('./redis');

const AdapterTest = Provider.AdapterTest;

const provider = new Provider('http://localhost', {
  adapter: RedisAdapter,
});
const test = new AdapterTest(provider);

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
