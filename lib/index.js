const { JWK } = require('node-jose');
const Provider = require('./provider');
const AdapterTest = require('./adapter_test');

module.exports = Provider;

module.exports.AdapterTest = AdapterTest;
module.exports.createKeyStore = JWK.createKeyStore;
module.exports.asKeyStore = JWK.asKeyStore;
module.exports.asKey = JWK.asKey;
