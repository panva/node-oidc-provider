const {
  get, set, isPlainObject, ..._
} = require('lodash');

const { JWA } = require('../consts');

const defaults = require('./defaults');
const { STABLE, DRAFTS } = require('./features');
const attention = require('./attention');

const SUBJECT_TYPES = new Set(['public', 'pairwise']);
const PKCE_METHODS = new Set(['plain', 'S256']);
const CHARSETS = new Set(['base-20', 'digits']);
const AUTH_ENDPOINTS = new Set(['token', 'introspection', 'revocation']);
const AUTH_METHODS = new Set([
  'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt',
  'tls_client_auth',
  'self_signed_tls_client_auth',
]);

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

function clientAuthDefaults(clientDefaults) {
  ['token_endpoint_auth_method', 'token_endpoint_auth_signing_alg'].forEach((prop) => {
    ['introspection', 'revocation'].forEach((endpoint) => {
      const endpointProp = prop.replace('token_', `${endpoint}_`);
      if (clientDefaults[prop] && !clientDefaults[endpointProp]) {
        set(clientDefaults, endpointProp, get(clientDefaults, prop));
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

module.exports = class Configuration {
  constructor(config) {
    authEndpointDefaults(config);

    Object.assign(this, _.cloneDeep(defaults));

    _.mergeWith(this, _.pick(config, Object.keys(defaults)), (objValue, srcValue, property) => {
      if (Array.isArray(objValue) || objValue instanceof Set || property === 'jwks') {
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
    clientAuthDefaults(this.clientDefaults);

    this.ensureMaps();
    this.ensureSets();

    // TODO: revert this back to its original state once
    // https://github.com/pillarjs/cookies/issues/109 lands
    this.removeCookiesSameSiteNone();

    this.fixResponseTypes();
    this.checkWhitelistedAlgs();
    this.collectScopes();
    this.collectPrompts();
    this.unpackArrayClaims();
    this.ensureOpenIdSub();
    this.removeAcrIfEmpty();
    this.collectClaims();
    this.defaultSigAlg();
    this.collectGrantTypes();
    this.checkSubjectTypes();
    this.checkPkceMethods();
    this.checkDependantFeatures();
    this.checkDeviceFlow();
    this.checkAuthMethods();
    this.checkTTL();

    this.logDraftNotice();
  }

  ensureMaps() {
    if (!(this.claims instanceof Map)) {
      if (!isPlainObject(this.claims)) {
        throw new Error('claims must be a plain javascript object or Map');
      }
      this.claims = new Map(Object.entries(this.claims));
    }
  }

  ensureSets() {
    [
      'scopes', 'subjectTypes', 'dynamicScopes', 'extraParams', 'acrValues',
      'tokenEndpointAuthMethods', 'introspectionEndpointAuthMethods', 'revocationEndpointAuthMethods',
    ].forEach((prop) => {
      if (!(this[prop] instanceof Set)) {
        if (!Array.isArray(this[prop])) {
          throw new Error(`${prop} must be an Array or Set`);
        }
        const setValue = new Set(this[prop]);
        if ('ack' in this[prop]) {
          setValue.ack = this[prop].ack;
        }
        this[prop] = setValue;
      }
    });
  }

  fixResponseTypes() {
    const types = new Set();

    this.responseTypes.forEach((type) => {
      const parsed = new Set(type.split(' '));

      if (
        (parsed.has('none') && parsed.size !== 1)
        || ![...parsed].every(Set.prototype.has.bind(supportedResponseTypes))
      ) {
        throw new Error(`unsupported response type: ${type}`);
      }

      types.add([...parsed].sort().join(' '));
    });

    this.responseTypes = [...types];
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

    if (this.scopes.has('offline_access')) {
      this.grantTypes.add('refresh_token');
    }

    if (this.features.clientCredentials.enabled) {
      this.grantTypes.add('client_credentials');
    }

    if (this.features.deviceFlow.enabled) {
      this.grantTypes.add('urn:ietf:params:oauth:grant-type:device_code');
    }
  }

  collectScopes() {
    const claimDefinedScopes = [];
    this.claims.forEach((value, key) => {
      if (isPlainObject(value) || Array.isArray(value)) {
        claimDefinedScopes.push(key);
      }
    });
    claimDefinedScopes.forEach((scope) => {
      if (typeof scope === 'string' && !this.scopes.has(scope)) {
        this.scopes.add(scope);
      }
      if (scope instanceof RegExp && !this.dynamicScopes.has(scope)) {
        this.dynamicScopes.add(scope);
      }
    });
  }

  collectPrompts() {
    this.prompts = new Set(['none']);
    this.interactions.policy.forEach(({ name, requestable }) => {
      if (requestable) {
        this.prompts.add(name);
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
    if (!this.acrValues.size) {
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

    this.claimsSupported = claims;
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

  setAlgs(prop, values, ...features) {
    if (features.length === 0 || features.every((feature) => {
      if (Array.isArray(feature)) {
        return feature.some(anyFeature => this.features[anyFeature].enabled);
      }
      return this.features[feature].enabled;
    })) {
      this[prop] = values;
    } else {
      this[prop] = [];
    }
  }

  defaultSigAlg() {
    const whitelist = this.whitelistedJWA;

    this.setAlgs('idTokenSigningAlgValues', whitelist.idTokenSigningAlgValues.filter(filterHSandNone));
    this.setAlgs('idTokenEncryptionAlgValues', whitelist.idTokenEncryptionAlgValues.slice());
    this.setAlgs('idTokenEncryptionEncValues', whitelist.idTokenEncryptionEncValues.slice(), 'encryption');

    this.setAlgs('requestObjectSigningAlgValues', whitelist.requestObjectSigningAlgValues.slice(), ['request', 'requestUri']);
    this.setAlgs('requestObjectEncryptionAlgValues', whitelist.requestObjectEncryptionAlgValues.filter(RegExp.prototype.test.bind(/^(A|P|dir$)/)), 'encryption', ['request', 'requestUri']);
    this.setAlgs('requestObjectEncryptionEncValues', whitelist.requestObjectEncryptionEncValues.slice(), 'encryption', ['request', 'requestUri']);

    this.setAlgs('userinfoSigningAlgValues', whitelist.userinfoSigningAlgValues.filter(filterHSandNone), 'jwtUserinfo');
    this.setAlgs('userinfoEncryptionAlgValues', whitelist.userinfoEncryptionAlgValues.slice(), 'jwtUserinfo', 'encryption');
    this.setAlgs('userinfoEncryptionEncValues', whitelist.userinfoEncryptionEncValues.slice(), 'jwtUserinfo', 'encryption');

    this.setAlgs('introspectionSigningAlgValues', whitelist.introspectionSigningAlgValues.filter(filterHSandNone), 'jwtIntrospection');
    this.setAlgs('introspectionEncryptionAlgValues', whitelist.introspectionEncryptionAlgValues.slice(), 'jwtIntrospection', 'encryption');
    this.setAlgs('introspectionEncryptionEncValues', whitelist.introspectionEncryptionEncValues.slice(), 'jwtIntrospection', 'encryption');

    this.setAlgs('authorizationSigningAlgValues', whitelist.authorizationSigningAlgValues.filter(filterHS), 'jwtResponseModes');
    this.setAlgs('authorizationEncryptionAlgValues', whitelist.authorizationEncryptionAlgValues.slice(), 'jwtResponseModes', 'encryption');
    this.setAlgs('authorizationEncryptionEncValues', whitelist.authorizationEncryptionEncValues.slice(), 'jwtResponseModes', 'encryption');

    this.endpointAuth('token');
    this.endpointAuth('introspection');
    this.endpointAuth('revocation');
  }

  endpointAuth(endpoint) {
    this[`${endpoint}EndpointAuthSigningAlgValues`] = this.whitelistedJWA[`${endpoint}EndpointAuthSigningAlgValues`];

    if (!this[`${endpoint}EndpointAuthMethods`].has('client_secret_jwt')) {
      _.remove(this[`${endpoint}EndpointAuthSigningAlgValues`], filterHS);
    }

    if (!this[`${endpoint}EndpointAuthMethods`].has('private_key_jwt')) {
      _.remove(this[`${endpoint}EndpointAuthSigningAlgValues`], RegExp.prototype.test.bind(/^((P|E|R)S\d{3}|EdDSA)$/));
    }

    if (!this[`${endpoint}EndpointAuthSigningAlgValues`].length) {
      this[`${endpoint}EndpointAuthSigningAlgValues`] = undefined;
    }
  }

  checkSubjectTypes() {
    if (!this.subjectTypes.size) {
      throw new Error('subjectTypes must not be empty');
    }

    this.subjectTypes.forEach((type) => {
      if (!SUBJECT_TYPES.has(type)) {
        throw new Error('only public and pairwise subjectTypes are supported');
      }
    });
  }

  checkPkceMethods() {
    if (!Array.isArray(this.pkceMethods)) {
      throw new Error('pkceMethods must be an array');
    }

    if (!this.pkceMethods.length) {
      throw new Error('pkceMethods must not be empty');
    }

    this.pkceMethods.forEach((type) => {
      if (!PKCE_METHODS.has(type)) {
        throw new Error('only plain and S256 code challenge methods are supported');
      }
    });
  }

  checkDependantFeatures() {
    const { features } = this;

    if (features.jwtIntrospection.enabled && !features.introspection.enabled) {
      throw new Error('jwtIntrospection is only available in conjuction with introspection');
    }

    if (features.jwtUserinfo.enabled && !features.userinfo.enabled) {
      throw new Error('jwtUserinfo is only available in conjuction with userinfo');
    }

    if (features.registrationManagement.enabled && !features.registration.enabled) {
      throw new Error('registrationManagement is only available in conjuction with registration');
    }

    if (
      (features.registration.enabled && features.registration.policies)
      && !features.registration.initialAccessToken
    ) {
      throw new Error('registration policies are only available in conjuction with adapter-backed initial access tokens');
    }
  }

  checkTTL() {
    Object.entries(this.ttl).forEach(([key, value]) => {
      if (
        (
          typeof value === 'function'
          && value.constructor.toString() !== 'function Function() { [native code] }'
        ) || (
          !Number.isSafeInteger(value)
          || value <= 0
        )
      ) {
        throw new Error(`ttl.${key} must be a positive integer or a regular function returning one`);
      }
    });
  }

  checkAuthMethods() {
    AUTH_ENDPOINTS.forEach((endpoint) => {
      if (this[`${endpoint}EndpointAuthMethods`]) {
        this[`${endpoint}EndpointAuthMethods`].forEach((method) => {
          if (!AUTH_METHODS.has(method)) {
            throw new Error(`only supported ${endpoint}EndpointAuthMethods are [${[...AUTH_METHODS]}]`);
          }
        });
      }
    });
  }

  checkDeviceFlow() {
    if (this.features.deviceFlow.enabled) {
      if (this.features.deviceFlow.charset !== undefined) {
        if (!CHARSETS.has(this.features.deviceFlow.charset)) {
          throw new Error('only supported charsets are "base-20" and "digits"');
        }
      }
      if (!/^[-* ]*$/.test(this.features.deviceFlow.mask)) {
        throw new Error('mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters');
      }
    }
  }

  removeCookiesSameSiteNone() {
    if (/^none$/i.test(this.cookies.short.sameSite)) {
      this.cookies.short.sameSite = undefined;
    }
    if (/^none$/i.test(this.cookies.long.sameSite)) {
      this.cookies.long.sameSite = undefined;
    }
  }

  logDraftNotice() {
    const ENABLED_DRAFTS = new Set();
    let throwDraft = false;

    Object.entries(this.features).forEach(([flag, { enabled, ack }]) => {
      const draft = DRAFTS.get(flag);
      if (
        draft
        && enabled && !STABLE.has(flag)
        && (Array.isArray(draft.version) ? !draft.version.includes(ack) : ack !== draft.version)
      ) {
        if (typeof ack !== 'undefined') {
          throwDraft = true;
        }
        ENABLED_DRAFTS.add(flag);
      }
    });

    /* eslint-disable no-restricted-syntax */
    for (const endpoint of AUTH_ENDPOINTS) {
      if (
        this[`${endpoint}EndpointAuthMethods`].has('tls_client_auth')
        && this[`${endpoint}EndpointAuthMethods`].ack !== DRAFTS.get('tlsClientAuth').version
      ) {
        ENABLED_DRAFTS.add('tlsClientAuth');
        if (typeof this[`${endpoint}EndpointAuthMethods`].ack !== 'undefined') {
          throwDraft = true;
        }
        break;
      }
    }

    for (const endpoint of AUTH_ENDPOINTS) {
      if (
        this[`${endpoint}EndpointAuthMethods`].has('self_signed_tls_client_auth')
        && this[`${endpoint}EndpointAuthMethods`].ack !== DRAFTS.get('selfSignedTlsClientAuth').version
      ) {
        ENABLED_DRAFTS.add('selfSignedTlsClientAuth');
        if (typeof this[`${endpoint}EndpointAuthMethods`].ack !== 'undefined') {
          throwDraft = true;
        }
        break;
      }
    }
    /* eslint-enable */

    /* istanbul ignore if */
    if (ENABLED_DRAFTS.size) {
      attention.info('The following draft features are enabled and their implemented version not acknowledged');
      ENABLED_DRAFTS.forEach((draft) => {
        const { name, type, url } = DRAFTS.get(draft);
        let { version } = DRAFTS.get(draft);

        if (Array.isArray(version)) {
          version = version[version.length - 1];
        }

        if (typeof version === 'number') {
          attention.info(`  - ${name} (This is an ${type}. URL: ${url})`);
        } else {
          attention.info(`  - ${name} (This is an ${type}. URL: ${url}. Acknowledging this feature's implemented version can be done with the string '${version}')`);
        }
      });
      attention.info('Breaking changes between draft version updates may occur and these will be published as MINOR semver oidc-provider updates.');
      attention.info('You may disable this notice and these potentially breaking updates by acknowledging the current draft version. See https://github.com/panva/node-oidc-provider/tree/master/docs/README.md#features');

      if (throwDraft) {
        throw new Error('An unacknowledged version of a draft feature is included in this oidc-provider version.');
      }
    }
  }
};
