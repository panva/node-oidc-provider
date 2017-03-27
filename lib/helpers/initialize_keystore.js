const jose = require('node-jose');
const assert = require('assert');
const { chain, map } = require('lodash');
const instance = require('./weak_cache');
const { DEV_KEYSTORE } = require('../consts');

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
    ].forEach((prop) => {
      conf[prop] = chain(conf[prop])
        .union(encryptionAlgs)
        .pullAll(conf.unsupported[prop])
        .value();
    });
  }

  const signingAlgs = key.algorithms('sign');
  [
    'idTokenSigningAlgValues',
    // 'requestObjectSigningAlgValues' if signed use private sig of clients (or their secret)
    // 'tokenEndpointAuthSigningAlgValues' if used then with client keys or their secret
    'userinfoSigningAlgValues',
  ].forEach((prop) => {
    conf[prop] = chain(conf[prop])
      .union(signingAlgs)
      .pullAll(conf.unsupported[prop])
      .value();
  });
}

module.exports = function initializeKeystore(conf = DEV_KEYSTORE) {
  if (conf === DEV_KEYSTORE) {
    /* eslint-disable no-console, no-multi-str */
    console.info('NOTICE: a quick start development-only sign key is used, \
you are expected to provide your own during provider#initialize');
    /* eslint-enable */
  }

  const getKeyStore = (() => {
    if (jose.JWK.isKeyStore(conf)) {
      const keystoreWrap = jose.JWK.createKeyStore();
      return Promise.all(map(conf.all(), key => keystoreWrap.add(key))).then(() => keystoreWrap);
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
