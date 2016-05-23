'use strict';

const _ = require('lodash');
const defaults = require('./defaults');
const MemoryAdapter = require('../adapters/memory_adapter');

class Configuration {
  constructor(config) {
    _.mergeWith(this, defaults, config, (objValue, srcValue) => {
      if (_.isArray(objValue)) {
        return srcValue;
      }

      return undefined;
    });

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

    this.idTokenEncryptionAlgValues = fullEncAlg;
    this.idTokenEncryptionEncValues = this.features.encryption ? encryptionEnc : [];
    this.idTokenSigningAlgValues = secretSig;
    this.requestObjectEncryptionAlgValues = [];
    this.requestObjectEncryptionEncValues = this.features.encryption ? encryptionEnc : [];
    this.requestObjectSigningAlgValues = fullSig;
    this.tokenEndpointAuthSigningAlgValues = _.without(fullSig, 'none');
    this.userinfoEncryptionAlgValues = fullEncAlg;
    this.userinfoEncryptionEncValues = this.features.encryption ? encryptionEnc : [];
    this.userinfoSigningAlgValues = secretSig;

    if (this.subjectTypes.indexOf('pairwise') !== -1 && !this.pairwiseSalt) {
      const msg = 'pairwiseSalt must be configured when pairwise subjectType is to be supported';
      throw new Error(msg);
    }

    this.claimsSupported = _.chain(this.scopes)
      .map(scope => _.keys(_.get(this.claims, scope, {})))
      .union(_.chain(this.claims)
        .pickBy(_.isNull)
        .keys()
        .value())
      .flatten()
      .sort()
      .value();

    const grantTypes = [];

    _.forEach(this.responseTypes, (responseType) => {
      if (responseType.indexOf('token') !== -1) {
        grantTypes.push('implicit');
      }
      if (responseType.indexOf('code') !== -1) {
        grantTypes.push('authorization_code');
      }
    });

    if (this.features.refreshToken || this.scopes.indexOf('offline_access') !== -1) {
      grantTypes.push('refresh_token');
    }

    if (this.features.clientCredentials) {
      grantTypes.push('client_credentials');
    }

    this.grantTypes = _.uniq(grantTypes);

    if (!this.adapter) {
      this.adapter = MemoryAdapter;
    }
  }
}

module.exports = function getConfiguration(config) {
  return new Configuration(config);
};
