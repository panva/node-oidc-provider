const {
  get, set, chain, ..._
} = require('lodash');

const { JWA } = require('../consts');

const defaults = require('./defaults');

function authEndpointDefaults(config) {
  [
    'tokenEndpointAuthMethods',
    'tokenEndpointAuthSigningAlgValues',
    'whitelistedJWA.tokenEndpointAuthSigningAlgValues',
  ].forEach((prop) => {
    ['introspection', 'revocation'].forEach((endpoint) => {
      if (get(config, prop) && !get(config, prop.replace('token', endpoint))) {
        set(config, prop.replace('token', endpoint), get(config, prop));
      }
    });
  });
}

function filterHS(alg) {
  return alg.startsWith('HS');
}

function filterHSandNone(alg) {
  return alg.startsWith('HS') || alg === 'none';
}

const supportedResponseTypes = new Set(['none', 'code', 'id_token', 'token']);

module.exports = class ConfigurationSchema {
  constructor(config) {
    authEndpointDefaults(config);

    Object.assign(this, _.cloneDeep(defaults));

    _.mergeWith(this, _.pick(config, Object.keys(defaults)), (objValue, srcValue) => {
      if (_.isArray(objValue)) {
        return srcValue;
      }

      if (srcValue instanceof Map) {
        Object.entries(objValue).forEach(([key, value]) => {
          if (!srcValue.has(key)) {
            srcValue.set(key, value);
          }
        });
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

    if (get(this, 'features.deviceFlow')) {
      if (!this.features.deviceFlow.charset) {
        set(this, 'features.deviceFlow.charset', 'base-20');
      }
      if (!this.features.deviceFlow.mask) {
        set(this, 'features.deviceFlow.mask', '****-****');
      }
      if (!this.features.deviceFlow.deviceInfo) {
        set(this, 'features.deviceFlow.deviceInfo', ctx => ({
          ip: ctx.ip,
          userAgent: ctx.get('user-agent'),
        }));
      }
    }

    this.ensureMaps();
    this.fixResponseTypes();
    this.checkWhitelistedAlgs();
    this.collectScopes();
    this.unpackArrayClaims();
    this.ensureOpenIdSub();
    this.removeAcrIfEmpty();
    this.collectClaims();
    this.defaultSigAlg();
    this.collectGrantTypes();
  }

  ensureMaps() {
    if (!(this.claims instanceof Map)) {
      this.claims = new Map(Object.entries(this.claims));
    }
  }

  fixResponseTypes() {
    const types = new Set();

    this.responseTypes.forEach((type) => {
      const parsed = new Set(type.split(' '));

      if (
        (parsed.has('none') && parsed.size !== 1)
        || !Array.from(parsed).every(Set.prototype.has.bind(supportedResponseTypes))
      ) {
        throw new Error(`unsupported response type: ${type}`);
      }

      types.add(Array.from(parsed).sort().join(' '));
    });

    this.responseTypes = Array.from(types);
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

    if (this.features.deviceFlow) {
      this.grantTypes.add('urn:ietf:params:oauth:grant-type:device_code');
    }
  }

  collectScopes() {
    const claimDefinedScopes = [];
    for (const [key, value] of this.claims.entries()) { // eslint-disable-line no-restricted-syntax
      if (_.isPlainObject(value) || Array.isArray(value)) {
        claimDefinedScopes.push(key);
      }
    }
    claimDefinedScopes.forEach((scope) => {
      if (!this.scopes.includes(scope) && typeof scope === 'string') {
        this.scopes.push(scope);
      }
      if (!this.dynamicScopes.includes(scope) && scope instanceof RegExp) {
        this.dynamicScopes.push(scope);
      }
    });
  }

  unpackArrayClaims() {
    this.claims.forEach((value, key) => {
      if (Array.isArray(value)) {
        this.claims.set(key, _.reduce(value, (accumulator, claim) => {
          const scope = accumulator;
          scope[claim] = null;
          return scope;
        }, {}));
      }
    });
  }

  ensureOpenIdSub() {
    if (!Object.keys(this.claims.get('openid')).includes('sub')) {
      this.claims.get('openid').sub = null;
    }
  }

  removeAcrIfEmpty() {
    if (!this.acrValues.length) {
      this.claims.delete('acr');
    }
  }

  collectClaims() {
    const claims = new Set();
    this.scopes.forEach((scope) => {
      if (this.claims.has(scope)) {
        Object.keys(this.claims.get(scope)).forEach(Set.prototype.add.bind(claims));
      }
    });
    this.dynamicScopes.forEach((scope) => {
      if (this.claims.has(scope)) {
        Object.keys(this.claims.get(scope)).forEach(Set.prototype.add.bind(claims));
      }
    });
    this.claims.forEach((value, key) => {
      if (value === null) claims.add(key);
    });

    this.claimsSupported = Array.from(claims);
  }

  checkWhitelistedAlgs() {
    Object.entries(this.whitelistedJWA).forEach(([key, value]) => {
      if (!JWA[key]) {
        throw new Error(`invalid property whitelistedJWA.${key} provided`);
      }

      if (!Array.isArray(value)) {
        throw new Error(`invalid type for whitelistedJWA.${key} provided, expected Array`);
      }

      value.forEach((alg) => {
        if (!JWA[key].includes(alg)) {
          throw new Error(`unsupported whitelistedJWA.${key} algorithm provided`);
        }
      });
    });
  }

  defaultSigAlg() {
    const whitelist = this.whitelistedJWA;
    this.idTokenEncryptionAlgValues = whitelist.idTokenEncryptionAlgValues.slice();
    this.idTokenEncryptionEncValues = this.features.encryption
      ? whitelist.idTokenEncryptionEncValues.slice() : [];
    this.idTokenSigningAlgValues = whitelist.idTokenSigningAlgValues
      .filter(filterHSandNone);

    this.requestObjectEncryptionAlgValues = this.features.encryption
      ? whitelist.requestObjectEncryptionAlgValues.filter(RegExp.prototype.test.bind(/^(A|P)/)) : [];
    this.requestObjectEncryptionEncValues = this.features.encryption
      ? whitelist.requestObjectEncryptionEncValues.slice() : [];
    this.requestObjectSigningAlgValues = whitelist.requestObjectSigningAlgValues.slice();

    this.endpointAuth('token');
    this.endpointAuth('introspection');
    this.endpointAuth('revocation');

    this.userinfoEncryptionAlgValues = whitelist.userinfoEncryptionAlgValues.slice();
    this.userinfoEncryptionEncValues = this.features.encryption
      ? whitelist.userinfoEncryptionEncValues.slice() : [];
    this.userinfoSigningAlgValues = whitelist.userinfoSigningAlgValues
      .filter(filterHSandNone);

    this.introspectionEncryptionAlgValues = whitelist.introspectionEncryptionAlgValues.slice();
    this.introspectionEncryptionEncValues = this.features.encryption
      ? whitelist.introspectionEncryptionEncValues.slice() : [];
    this.introspectionSigningAlgValues = whitelist.introspectionSigningAlgValues
      .filter(filterHSandNone);

    this.authorizationEncryptionAlgValues = whitelist.authorizationEncryptionAlgValues.slice();
    this.authorizationEncryptionEncValues = this.features.encryption
      ? whitelist.authorizationEncryptionEncValues.slice() : [];
    this.authorizationSigningAlgValues = whitelist.authorizationSigningAlgValues
      .filter(filterHS);
  }

  endpointAuth(endpoint) {
    this[`${endpoint}EndpointAuthSigningAlgValues`] = this.whitelistedJWA[`${endpoint}EndpointAuthSigningAlgValues`];

    if (!this[`${endpoint}EndpointAuthMethods`].includes('client_secret_jwt')) {
      _.remove(this[`${endpoint}EndpointAuthSigningAlgValues`], filterHS);
    }

    if (!this[`${endpoint}EndpointAuthMethods`].includes('private_key_jwt')) {
      _.remove(this[`${endpoint}EndpointAuthSigningAlgValues`], RegExp.prototype.test.bind(/^(E|P|R)S/));
    }

    if (!this[`${endpoint}EndpointAuthSigningAlgValues`].length) {
      this[`${endpoint}EndpointAuthSigningAlgValues`] = undefined;
    }
  }
};
