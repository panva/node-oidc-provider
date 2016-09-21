'use strict';

const _ = require('lodash');
const defaults = require('./defaults');

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
  // asymmetric
  'RSA-OAEP',
  'RSA-OAEP-256',
  'RSA1_5',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A256KW',
  // symmetric
  'A128GCMKW',
  'A192GCMKW',
  'A256GCMKW',
  'A128KW',
  'A192KW',
  'A256KW',
  'PBES2-HS256+A128KW',
  'PBES2-HS384+A192KW',
  'PBES2-HS512+A256KW',
];

module.exports = class ConfigurationSchema {
  constructor(config) {
    _.mergeWith(this, defaults, config, (objValue, srcValue) => {
      if (_.isArray(objValue)) {
        return srcValue;
      }

      return undefined;
    });

    this.defaultSigAlg();
    this.collectClaims();
    this.collectGrantTypes();
  }

  collectGrantTypes() {
    this.grantTypes = new Set();

    this.responseTypes.forEach((responseType) => {
      if (responseType.indexOf('token') !== -1) {
        this.grantTypes.add('implicit');
      }
      if (responseType.indexOf('code') !== -1) {
        this.grantTypes.add('authorization_code');
      }
    });

    if (this.features.refreshToken || this.scopes.indexOf('offline_access') !== -1) {
      this.grantTypes.add('refresh_token');
    }

    if (this.features.clientCredentials) {
      this.grantTypes.add('client_credentials');
    }
  }

  collectClaims() {
    this.claimsSupported = _.chain(this.scopes)
      .map(scope => _.keys(_.get(this.claims, scope, {})))
      .union(_.chain(this.claims)
        .pickBy(_.isNull)
        .keys()
        .value())
      .flatten()
      .sort()
      .value();
  }

  defaultSigAlg() {
    this.idTokenEncryptionAlgValues = _.clone(fullEncAlg);
    this.idTokenEncryptionEncValues = this.features.encryption ? _.clone(encryptionEnc) : [];
    this.idTokenSigningAlgValues = _.clone(secretSig);
    this.requestObjectEncryptionAlgValues = [];
    this.requestObjectEncryptionEncValues = this.features.encryption ? _.clone(encryptionEnc) : [];
    this.requestObjectSigningAlgValues = _.clone(fullSig);
    this.tokenEndpointAuthSigningAlgValues = _.without(fullSig, 'none');
    this.userinfoEncryptionAlgValues = _.clone(fullEncAlg);
    this.userinfoEncryptionEncValues = this.features.encryption ? _.clone(encryptionEnc) : [];
    this.userinfoSigningAlgValues = _.clone(secretSig);
  }
};
