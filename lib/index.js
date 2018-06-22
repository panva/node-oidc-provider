const { JWK: { createKeyStore, asKeyStore, asKey } } = require('node-jose');

const Provider = require('./provider');
const AdapterTest = require('./adapter_test');
const errors = require('./helpers/errors');

Object.assign(Provider, {
  AdapterTest,
  createKeyStore,
  asKeyStore,
  asKey,
  errors,
});

module.exports = Provider;
