const { JWK: { createKeyStore, asKeyStore, asKey } } = require('node-jose');
const Provider = require('./provider');
const AdapterTest = require('./adapter_test');

Object.assign(Provider, {
  AdapterTest,
  createKeyStore,
  asKeyStore,
  asKey,
});

module.exports = Provider;
