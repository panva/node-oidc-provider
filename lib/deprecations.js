/* eslint-disable */
'use strict';

const _ = require('lodash');
const util = require('util');

/* istanbul ignore next */
function deprecateApis(Provider) {
Provider.prototype.get = util.deprecate(function deprecatedGet(name) {
  switch (name) {
    case 'OAuthToken':
    case 'Account':
    case 'IdToken':
    case 'Client':
    case 'Session':
    case 'AccessToken':
    case 'AuthorizationCode':
    case 'RefreshToken':
    case 'ClientCredentials':
    case 'RegistrationAccessToken':
    case 'InitialAccessToken':
      return this[name];
    default:
      throw new Error('unrecognized model');
  }
}, 'WARNING: provider.get(modelName) is deprecated and will be removed before 1.0, use eg. \
provider.AccessToken directly');

Provider.prototype.addKey = util.deprecate(function deprecatedAddKey(key) {
  return this.keystore.add(key).then(jwk => {
    // check if private key was added
    try {
      jwk.toPEM(true);
    } catch (err) {
      this.keystore.remove(jwk);
      throw new Error('only private keys should be added');
    }

    if (this.configuration('features.encryption')) {
      const encryptionAlgs = jwk.algorithms('wrap');
      [
        // 'idTokenEncryptionAlgValues',
        'requestObjectEncryptionAlgValues',
        // 'userinfoEncryptionAlgValues',
      ].forEach(prop => {
        this.configuration()[prop] = _.union(this.configuration()[prop], encryptionAlgs);
      });
    }

    const signingAlgs = jwk.algorithms('sign');
    [
      'idTokenSigningAlgValues',
      // 'requestObjectSigningAlgValues',
      // 'tokenEndpointAuthSigningAlgValues',
      'userinfoSigningAlgValues',
    ].forEach(prop => {
      this.configuration()[prop] = _.union(this.configuration()[prop], signingAlgs);
    });

    return Promise.resolve(jwk);
  });
}, 'WARNING: provider.addKey is deprecated and will be removed before 1.0, you should provide \
complete keystore as config.keystore');
}

module.exports = deprecateApis;
