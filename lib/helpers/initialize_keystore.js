const assert = require('assert');

const { JWK: { isKeyStore, asKeyStore } } = require('node-jose');
const { chain } = require('lodash');

const { DEV_KEYSTORE } = require('../consts');

const attention = require('./attention');
const instance = require('./weak_cache');

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
    'introspectionSigningAlgValues',
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
    /* eslint-disable no-multi-str */
    attention.warn('a quick start development-only sign key is used, \
you are expected to provide your own during provider#initialize');
    /* eslint-enable */
  }

  const keystore = await getKeyStore(conf);
  const idTokenFromAuth = instance(this).configuration('responseTypes').find(type => type.includes('id_token'));
  const idTokenSigningAlgValues = instance(this).configuration('idTokenSigningAlgValues');
  const onlyNone = idTokenSigningAlgValues.length === 1 && idTokenSigningAlgValues[0] === 'none';
  const perform256check = idTokenFromAuth || !onlyNone;
  if (perform256check) {
    assert(
      keystore.get({ use: 'sig', alg: 'RS256' }),
      'RS256 signing must be supported but no viable key was provided',
    );
  }
  instance(this).keystore = keystore;
  keystore.all().forEach(registerKey, this);
};
