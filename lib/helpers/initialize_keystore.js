const { strict: assert } = require('assert');

const { JWKS } = require('jose');
const hash = require('object-hash');

const { DEV_KEYSTORE } = require('../consts');

const runtimeSupport = require('./runtime_support');
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
      conf[prop] = [...new Set([...conf[prop], ...encryptionAlgs])]
        .filter((v) => conf.whitelistedJWA[prop].includes(v));
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
    conf[prop] = [...new Set([...conf[prop], ...signingAlgs])]
      .filter((v) => conf.whitelistedJWA[prop].includes(v));
  });
}

module.exports = function initializeKeystore(jwks) {
  if (hash(jwks) === hash(DEV_KEYSTORE)) {
    /* eslint-disable no-multi-str */
    attention.warn('a quick start development-only signing keys are used, you are expected to \
provide your own in configuration "jwks" property');
    /* eslint-enable */
  }

  let keystore;
  try {
    keystore = JWKS.asKeyStore(jwks);
  } catch (err) {
    throw new Error('keystore must be a JSON Web Key Set formatted object');
  }

  if (!runtimeSupport.shake256 && keystore.get({ kty: 'OKP', crv: 'Ed448' })) {
    throw new Error('Ed448 keys are only fully supported to sign ID Tokens with in node runtime >= 12.8.0');
  }

  instance(this).keystore = keystore;
  let warned;
  for (const key of keystore) { // eslint-disable-line no-restricted-syntax
    if (!warned && keystore.all({ kid: key.kid }).length > 1) {
      warned = true;
      /* eslint-disable no-multi-str */
      attention.warn('different keys within the keystore SHOULD use distinct `kid` values, with \
your current keystore you should expect interoperability issues with your clients');
      /* eslint-enable */
    }
    registerKey.call(this, key);
  }
};
