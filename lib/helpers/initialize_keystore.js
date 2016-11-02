'use strict';

const jose = require('node-jose');
const assert = require('assert');
const _ = require('lodash');
const instance = require('./weak_cache');
const DEV_KEYSTORE = require('../consts').DEV_KEYSTORE;

function registerKey(key) {
  try {
    key.toPEM(true);
  } catch (err) {
    throw new Error('only private RSA or EC keys should be part of keystore configuration');
  }

  const conf = instance(this).configuration();

  if (conf.features.encryption) {
    const encryptionAlgs = key.algorithms('wrap');
    [
      // 'idTokenEncryptionAlgValues',
      'requestObjectEncryptionAlgValues',
      // 'userinfoEncryptionAlgValues',
    ].forEach((prop) => { conf[prop] = _.union(conf[prop], encryptionAlgs); });
  }

  const signingAlgs = key.algorithms('sign');
  [
    'idTokenSigningAlgValues',
    // 'requestObjectSigningAlgValues' if signed use private sig of clients (or their secret)
    // 'tokenEndpointAuthSigningAlgValues' if used then with client keys or their secret
    'userinfoSigningAlgValues',
  ].forEach((prop) => { conf[prop] = _.union(conf[prop], signingAlgs); });
}

module.exports = function initializeKeystore(keystoreConf) {
  const conf = (() => {
    if (typeof keystoreConf === 'undefined') {
      /* eslint-disable no-console, no-multi-str */
      console.info('NOTICE: a quick start development-only sign key is used, \
you are expected to provide your own during provider#initialize');
      /* eslint-enable */
      return DEV_KEYSTORE;
    }

    return keystoreConf;
  })();

  const getKeyStore = (() => {
    if (jose.JWK.isKeyStore(conf)) {
      const keystoreWrap = jose.JWK.createKeyStore();
      return Promise.all(_.map(conf.all(), key => keystoreWrap.add(key))).then(() => keystoreWrap);
    }

    return Promise.resolve().then(() => jose.JWK.asKeyStore(conf));
  })();

  return getKeyStore.then((keystore) => {
    assert(keystore.get({
      use: 'sig',
      alg: 'RS256',
    }), 'RS256 signing must be supported but no viable key was provided');
    instance(this).keystore = keystore;

    keystore.all().forEach(registerKey.bind(this));
  });
};
