'use strict';

const _ = require('lodash');
const MemoryAdapter = require('../adapters/memory_adapter');
const defaults = require('./defaults');

class Configuration {
  constructor(config) {
    _.merge(this, defaults, config);

    const encryptionEnc = [
      'A128CBC-HS256',
      'A128GCM',
      'A192CBC-HS384',
      'A192GCM',
      'A256CBC-HS512',
      'A256GCM',
    ];

    const secretSig = [
      'none',
      'HS256',
      'HS384',
      'HS512',
    ];

    const fullSig = [
      'none',
      'HS256',
      'HS384',
      'HS512',
      'RS256',
      'RS384',
      'RS512',
      'PS256',
      'PS384',
      'PS512',
      'ES256',
      'ES384',
      'ES512',
    ];

    const fullEncAlg = [
      'RSA-OAEP',
      'RSA-OAEP-256',
      'RSA1_5',
      'ECDH-ES',
      'ECDH-ES+A128KW',
      'ECDH-ES+A192KW',
      'ECDH-ES+A256KW',
    ];

    this.idTokenEncryptionAlgValuesSupported = fullEncAlg;
    this.idTokenEncryptionEncValuesSupported = this.features.encryption ?
      encryptionEnc : [];
    this.idTokenSigningAlgValuesSupported = secretSig;
    this.requestObjectEncryptionAlgValuesSupported = [];
    this.requestObjectEncryptionEncValuesSupported = this.features.encryption ?
      encryptionEnc : [];
    this.requestObjectSigningAlgValuesSupported = fullSig;
    this.tokenEndpointAuthSigningAlgValuesSupported =
      _.without(fullSig, 'none');
    this.userinfoEncryptionAlgValuesSupported = fullEncAlg;
    this.userinfoEncryptionEncValuesSupported = this.features.encryption ?
      encryptionEnc : [];
    this.userinfoSigningAlgValuesSupported = secretSig;

    this.adapters = this.adapters || {};
    this.adapters.MemoryAdapter = MemoryAdapter;
    this.adapter = this.adapter || 'MemoryAdapter';

    this.claimsSupported = _.chain(this.scopes)
      .map(scope => _.keys(_.get(this.claims, scope, {})))
      .union(_.chain(this.claims)
        .pickBy(_.isNull)
        .keys()
        .value())
      .flatten()
      .sort()
      .value();

    const grantTypesSupported = [];

    _.forEach(this.responseTypesSupported, responseType => {
      if (responseType.indexOf('token') !== -1) {
        grantTypesSupported.push('implicit');
      }
      if (responseType.indexOf('code') !== -1) {
        grantTypesSupported.push('authorization_code');
      }
    });

    if (this.features.refreshToken ||
      this.scopes.indexOf('offline_access') !== -1) {
      grantTypesSupported.push('refresh_token');
    }

    if (this.features.clientCredentials) {
      grantTypesSupported.push('client_credentials');
    }

    this.grantTypesSupported = _.uniq(grantTypesSupported);
  }
}

module.exports = function getConfiguration(config) {
  return new Configuration(config);
};
