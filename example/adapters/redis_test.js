// node example/adapters/redis_test.js

/* eslint-disable no-console */

const Provider = require('../../lib');
const RedisAdapter = require('./redis');

const { AdapterTest } = Provider;

const provider = new Provider('http://localhost');
const test = new AdapterTest(provider);

provider.initialize({ adapter: RedisAdapter })
  .then(() => test.execute())
  .then(() => {
    console.log('tests passed');
    process.exit();
  })
  .catch((err) => {
    console.dir(err);
    process.exit(1);
  });
