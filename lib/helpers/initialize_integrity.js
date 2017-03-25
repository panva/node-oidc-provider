const jose = require('node-jose');
const assert = require('assert');
const { map } = require('lodash');
const instance = require('./weak_cache');
const { DEV_INTEGRITY } = require('../consts');

module.exports = function initializeIntegrity(integrityConf) {
  const conf = (() => {
    if (typeof integrityConf === 'undefined') {
      /* eslint-disable no-console, no-multi-str */
      console.info('NOTICE: a quick start development-only integrity key is used, \
you are expected to provide your own during provider#initialize');
      /* eslint-enable */
      return DEV_INTEGRITY;
    }

    return integrityConf;
  })();

  const getKeyStore = (() => {
    if (jose.JWK.isKeyStore(conf)) {
      const keystoreWrap = jose.JWK.createKeyStore();
      return Promise.all(map(conf.all(), key => keystoreWrap.add(key))).then(() => keystoreWrap);
    }

    return Promise.resolve().then(() => jose.JWK.asKeyStore(conf));
  })();

  return getKeyStore.then((integrity) => {
    const firstSigKey = integrity.get();
    assert(firstSigKey, 'at least one key must be provided in integrity keystore');
    assert(firstSigKey.algorithms('sign').length, 'integrity keystore\'s first key must support signing');
    instance(this).integrity = integrity;
  });
};
