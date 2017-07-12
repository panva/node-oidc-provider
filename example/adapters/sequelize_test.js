// node example/adapters/sequelize_test.js

/* eslint-disable no-console */

const Provider = require('../../lib');
const SequelizeAdapter = require('./sequelize');

const { AdapterTest } = Provider;

const provider = new Provider('http://localhost');
const test = new AdapterTest(provider);

provider.initialize({ adapter: SequelizeAdapter })
  .then(() => test.execute())
  .then(() => {
    console.log('tests passed');
    process.exit();
  })
  .catch((err) => {
    console.dir(err);
    process.exit(1);
  });
