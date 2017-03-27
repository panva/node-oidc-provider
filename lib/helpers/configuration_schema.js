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
    _.mergeWith(this, defaults, _.pick(config, Object.keys(defaults)), (objValue, srcValue) => {
      if (_.isArray(objValue)) {
        return srcValue;
      }

      return undefined;
    });
    this.collectScopes();
    this.unpackArrayClaims();
    this.ensureOpenIdSub();

    this.removeAcrIfEmpty();
    this.collectClaims();
    this.defaultSigAlg();
    this.removeSigAlg();
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

    if (this.features.alwaysIssueRefresh || this.scopes.indexOf('offline_access') !== -1) {
      this.grantTypes.add('refresh_token');
    }

    if (this.features.clientCredentials) {
      this.grantTypes.add('client_credentials');
    }
  }

  collectScopes() {
    const scopes = _.chain(this.claims)
      .pickBy(entry => _.isPlainObject(entry) || Array.isArray(entry))
      .keys()
      .value();

    scopes.forEach((scope) => {
      if (this.scopes.indexOf(scope) === -1) {
        this.scopes.push(scope);
      }
    });
  }

  unpackArrayClaims() {
    _.forEach(this.claims, (value, key) => {
      if (Array.isArray(value)) {
        this.claims[key] = _.reduce(value, (accumulator, claim) => {
          const scope = accumulator;
          scope[claim] = null;
          return scope;
        }, {});
      }
    });
  }

  ensureOpenIdSub() {
    if (Object.keys(this.claims.openid).indexOf('sub') === -1) {
      this.claims.openid.sub = null;
    }
  }

  removeAcrIfEmpty() {
    if (!this.acrValues.length) {
      delete this.claims.acr;
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
    this.idTokenEncryptionAlgValues = fullEncAlg.slice();
    this.idTokenEncryptionEncValues = this.features.encryption ? encryptionEnc.slice() : [];
    this.idTokenSigningAlgValues = secretSig.slice();

    this.requestObjectEncryptionAlgValues = [];
    this.requestObjectEncryptionEncValues = this.features.encryption ? encryptionEnc.slice() : [];
    this.requestObjectSigningAlgValues = fullSig.slice();

    this.tokenEndpointAuthSigningAlgValues = _.without(fullSig, 'none');

    if (this.tokenEndpointAuthMethods.indexOf('client_secret_jwt') === -1) {
      _.remove(this.tokenEndpointAuthSigningAlgValues, alg => alg.startsWith('HS'));
    }

    if (this.tokenEndpointAuthMethods.indexOf('private_key_jwt') === -1) {
      _.remove(this.tokenEndpointAuthSigningAlgValues, alg => alg.match(/^(E|P|R)S/));
    }

    if (!this.tokenEndpointAuthSigningAlgValues.length) {
      this.tokenEndpointAuthSigningAlgValues = undefined;
    }

    this.userinfoEncryptionAlgValues = fullEncAlg.slice();
    this.userinfoEncryptionEncValues = this.features.encryption ? encryptionEnc.slice() : [];
    this.userinfoSigningAlgValues = secretSig.slice();
  }

  omitUnsupported(property) {
    _.pullAll(this[property], _.get(this, `unsupported.${property}`, []));
  }

  removeSigAlg() {
    this.omitUnsupported('idTokenEncryptionAlgValues');
    this.omitUnsupported('idTokenEncryptionEncValues');
    this.omitUnsupported('idTokenSigningAlgValues');
    this.omitUnsupported('requestObjectEncryptionEncValues');
    this.omitUnsupported('requestObjectSigningAlgValues');
    this.omitUnsupported('tokenEndpointAuthSigningAlgValues');
    this.omitUnsupported('userinfoEncryptionAlgValues');
    this.omitUnsupported('userinfoEncryptionEncValues');
    this.omitUnsupported('userinfoSigningAlgValues');
  }
};
