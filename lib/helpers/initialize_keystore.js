const assert = require('assert');

const { JWKS } = require('@panva/jose');
const { chain, isEqual } = require('lodash');

const { DEV_KEYSTORE } = require('../consts');

const attention = require('./attention');
const instance = require('./weak_cache');

const KEY_TYPES = new Set(['RSA', 'EC', 'OKP']);

function registerKey(key) {
  try {
    assert(KEY_TYPES.has(key.kty) && key.private);
  } catch (err) {
    throw new Error('only private RSA, EC or OKP keys should be part of keystore configuration');
  }

  const conf = instance(this).configuration();

  if (conf.features.encryption.enabled) {
    const encryptionAlgs = [...key.algorithms('wrapKey'), ...key.algorithms('deriveKey')];

    [
      // 'idTokenEncryptionAlgValues',
      'requestObjectEncryptionAlgValues',
      // 'userinfoEncryptionAlgValues',
    ].forEach((prop) => {
      conf[prop] = chain(conf[prop])
        .union([...encryptionAlgs])
        .intersection(conf.whitelistedJWA[prop])
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
    'authorizationSigningAlgValues',
  ].forEach((prop) => {
    conf[prop] = chain(conf[prop])
      .union([...signingAlgs])
      .intersection(conf.whitelistedJWA[prop])
      .value();
  });
}

module.exports = function initializeKeystore(jwks) {
  if (isEqual(jwks, DEV_KEYSTORE)) {
    /* eslint-disable no-multi-str */
    attention.warn('a quick start development-only signing keys are used, you are expected to \
provide your own in configuration "jwks" property');
    /* eslint-enable */
  }

  let keystore;
  try {
    keystore = JWKS.KeyStore.fromJWKS(jwks);
  } catch (err) {
    throw new Error('keystore must be a JSON Web Key Set formatted object');
  }
  instance(this).keystore = keystore;
  keystore.all().forEach(registerKey, this);
};
