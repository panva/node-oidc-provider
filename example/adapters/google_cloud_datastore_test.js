// node example/adapters/google_cloud_datastore_test.js

/* eslint-disable no-console */

const Provider = require('../../lib');

const GCDAdapter = require('./google_cloud_datastore');

const { AdapterTest } = Provider;

const provider = new Provider('http://localhost');
const test = new AdapterTest(provider);

provider.initialize({ adapter: GCDAdapter })
  .then(() => test.execute())
  .then(() => {
    console.log('tests passed');
    process.exit();
  })
  .catch((err) => {
    console.dir(err);
    process.exit(1);
  });
