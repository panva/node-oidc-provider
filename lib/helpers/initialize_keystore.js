const { JWK: { isKeyStore, asKeyStore } } = require('node-jose');
const assert = require('assert');
const { chain } = require('lodash');
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

async function getKeyStore(conf) {
  if (isKeyStore(conf)) return conf;
  return asKeyStore(conf);
}

module.exports = async function initializeKeystore(conf = DEV_KEYSTORE) {
  if (conf === DEV_KEYSTORE) {
    /* eslint-disable no-console, no-multi-str */
    console.info('NOTICE: a quick start development-only sign key is used, \
you are expected to provide your own during provider#initialize');
    /* eslint-enable */
  }

  const keystore = await getKeyStore(conf);
  const implicit = instance(this).configuration('responseTypes').find(type => type.includes('token'));
  if (implicit) {
    assert(
      keystore.get({ use: 'sig', alg: 'RS256' }),
      'RS256 signing must be supported but no viable key was provided',
    );
  }
  instance(this).keystore = keystore;
  keystore.all().forEach(registerKey, this);
};
