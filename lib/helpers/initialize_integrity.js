const { JWK: { isKeyStore, asKeyStore } } = require('node-jose');
const assert = require('assert');
const instance = require('./weak_cache');
const { DEV_INTEGRITY } = require('../consts');


async function getKeyStore(conf) {
  if (isKeyStore(conf)) return conf;
  return asKeyStore(conf);
}

module.exports = async function initializeIntegrity(conf = DEV_INTEGRITY) {
  if (conf === DEV_INTEGRITY) {
    /* eslint-disable no-console, no-multi-str */
    console.info('NOTICE: a quick start development-only integrity key is used, \
    you are expected to provide your own during provider#initialize');
    /* eslint-enable */
  }

  const integrity = await getKeyStore(conf);
  const firstSigKey = integrity.get();
  assert(firstSigKey, 'at least one key must be provided in integrity keystore');
  assert(firstSigKey.algorithms('sign').length, 'integrity keystore\'s first key must support signing');
  instance(this).integrity = integrity;
};
