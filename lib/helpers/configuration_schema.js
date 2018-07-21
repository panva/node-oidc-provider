const {
  get, set, chain, ..._
} = require('lodash');

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

function authEndpointDefaults(config) {
  [
    'tokenEndpointAuthMethods',
    'tokenEndpointAuthSigningAlgValues',
    'unsupported.tokenEndpointAuthSigningAlgValues',
  ].forEach((prop) => {
    ['introspection', 'revocation'].forEach((endpoint) => {
      if (get(config, prop) && !get(config, prop.replace('token', endpoint))) {
        set(config, prop.replace('token', endpoint), get(config, prop));
      }
    });
  });
}

module.exports = class ConfigurationSchema {
  constructor(config) {
    authEndpointDefaults(config);

    _.mergeWith(this, defaults, _.pick(config, Object.keys(defaults)), (objValue, srcValue) => {
      if (_.isArray(objValue)) {
        return srcValue;
      }

      return undefined;
    });

    if (get(this, 'features.oauthNativeApps')) {
      set(this, 'features.pkce.forcedForNative', true);
    }

    if (get(this, 'features.pkce') && !get(this, 'features.pkce.supportedMethods')) {
      set(this, 'features.pkce.supportedMethods', ['S256']);
    }

    if (get(this, 'features.requestUri') === true) {
      set(this, 'features.requestUri', { requireRequestUriRegistration: true });
    }

    if (get(this, 'features.deviceCode')) {
      if (!this.features.deviceCode.charset) {
        set(this, 'features.deviceCode.charset', 'BCDFGHJKLMNPQRSTVWXZ');
      }
      if (!this.features.deviceCode.mask) {
        set(this, 'features.deviceCode.mask', '****-****');
      }
      if (!this.features.deviceCode.deviceInfo) {
        set(this, 'features.deviceCode.deviceInfo', ctx => ({
          ip: ctx.ip,
          userAgent: ctx.get('user-agent'),
        }));
      }
    }

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
      if (responseType.includes('token')) {
        this.grantTypes.add('implicit');
      }
      if (responseType.includes('code')) {
        this.grantTypes.add('authorization_code');
      }
    });

    if (this.features.alwaysIssueRefresh || this.scopes.includes('offline_access')) {
      this.grantTypes.add('refresh_token');
    }

    if (this.features.clientCredentials) {
      this.grantTypes.add('client_credentials');
    }

    if (this.features.deviceCode) {
      this.grantTypes.add('urn:ietf:params:oauth:grant-type:device_code');
    }
  }

  collectScopes() {
    Object.entries(this.claims).map(([key, value]) => {
      if (_.isPlainObject(value) || Array.isArray(value)) {
        return key;
      }
      return undefined;
    }).filter(Boolean).forEach((scope) => {
      if (!this.scopes.includes(scope)) {
        this.scopes.push(scope);
      }
    });
  }

  unpackArrayClaims() {
    Object.entries(this.claims).forEach(([key, value]) => {
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
    if (!Object.keys(this.claims.openid).includes('sub')) {
      this.claims.openid.sub = null;
    }
  }

  removeAcrIfEmpty() {
    if (!this.acrValues.length) {
      delete this.claims.acr;
    }
  }

  collectClaims() {
    const claims = new Set();
    this.scopes.forEach((scope) => {
      if (this.claims[scope]) {
        Object.keys(this.claims[scope]).forEach(claims.add.bind(claims));
      }
    });
    Object.entries(this.claims).forEach(([key, value]) => {
      if (value === null) claims.add(key);
    });

    this.claimsSupported = Array.from(claims);
  }

  defaultSigAlg() {
    this.idTokenEncryptionAlgValues = fullEncAlg.slice();
    this.idTokenEncryptionEncValues = this.features.encryption ? encryptionEnc.slice() : [];
    this.idTokenSigningAlgValues = secretSig.slice();

    this.requestObjectEncryptionAlgValues = this.features.encryption ? fullEncAlg.filter(alg => alg.match(/^(A|P)/)) : [];
    this.requestObjectEncryptionEncValues = this.features.encryption ? encryptionEnc.slice() : [];
    this.requestObjectSigningAlgValues = fullSig.slice();

    this.endpointAuth('token');
    this.endpointAuth('introspection');
    this.endpointAuth('revocation');

    this.userinfoEncryptionAlgValues = fullEncAlg.slice();
    this.userinfoEncryptionEncValues = this.features.encryption ? encryptionEnc.slice() : [];
    this.userinfoSigningAlgValues = secretSig.slice();

    this.introspectionEncryptionAlgValues = fullEncAlg.slice();
    this.introspectionEncryptionEncValues = this.features.encryption ? encryptionEnc.slice() : [];
    this.introspectionSigningAlgValues = secretSig.slice();
  }

  endpointAuth(endpoint) {
    this[`${endpoint}EndpointAuthSigningAlgValues`] = _.without(fullSig, 'none');

    if (!this[`${endpoint}EndpointAuthMethods`].includes('client_secret_jwt')) {
      _.remove(this[`${endpoint}EndpointAuthSigningAlgValues`], alg => alg.startsWith('HS'));
    }

    if (!this[`${endpoint}EndpointAuthMethods`].includes('private_key_jwt')) {
      _.remove(this[`${endpoint}EndpointAuthSigningAlgValues`], alg => alg.match(/^(E|P|R)S/));
    }

    if (!this[`${endpoint}EndpointAuthSigningAlgValues`].length) {
      this[`${endpoint}EndpointAuthSigningAlgValues`] = undefined;
    }
  }

  omitUnsupported(property) {
    _.pullAll(this[property], get(this, `unsupported.${property}`, []));
  }

  removeSigAlg() {
    this.omitUnsupported('idTokenEncryptionAlgValues');
    this.omitUnsupported('idTokenEncryptionEncValues');
    this.omitUnsupported('idTokenSigningAlgValues');
    this.omitUnsupported('requestObjectEncryptionEncValues');
    this.omitUnsupported('requestObjectSigningAlgValues');
    this.omitUnsupported('tokenEndpointAuthSigningAlgValues');
    this.omitUnsupported('introspectionEndpointAuthSigningAlgValues');
    this.omitUnsupported('revocationEndpointAuthSigningAlgValues');
    this.omitUnsupported('userinfoEncryptionAlgValues');
    this.omitUnsupported('userinfoEncryptionEncValues');
    this.omitUnsupported('userinfoSigningAlgValues');
    this.omitUnsupported('introspectionEncryptionAlgValues');
    this.omitUnsupported('introspectionEncryptionEncValues');
    this.omitUnsupported('introspectionSigningAlgValues');
  }
};
