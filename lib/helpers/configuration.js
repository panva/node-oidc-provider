const { deprecate } = require('util');

const { JWA } = require('../consts');

const get = require('./_/get');
const isPlainObject = require('./_/is_plain_object');
const remove = require('./_/remove');
const merge = require('./_/merge');
const pick = require('./_/pick');
const set = require('./_/set');
const formatters = require('./formatters');
const docs = require('./docs');
const getDefaults = require('./defaults');
const { STABLE, DRAFTS } = require('./features');
const attention = require('./attention');
const instance = require('./weak_cache');

function authEndpointDefaults(config) {
  [
    'tokenEndpointAuthMethods',
    'tokenEndpointAuthSigningAlgValues',
    'enabledJWA.tokenEndpointAuthSigningAlgValues',
  ].forEach((prop) => {
    ['introspection', 'revocation'].forEach((endpoint) => {
      if (get(config, prop) && !get(config, prop.replace('token', endpoint))) {
        set(config, prop.replace('token', endpoint), get(config, prop));
      }
    });
  });
}

function featuresTypeErrorCheck({ features }) {
  for (const value of Object.values(features)) { // eslint-disable-line no-restricted-syntax
    if (typeof value === 'boolean') {
      throw new TypeError('features are no longer enabled/disabled with a boolean value, please see the docs');
    }
  }
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

const filterAsymmetricSig = RegExp.prototype.test.bind(/^(?:PS(?:256|384|512)|RS(?:256|384|512)|ES(?:256K?|384|512)|EdDSA)$/);

function filterHSandNone(alg) {
  return alg.startsWith('HS') || alg === 'none';
}

const supportedResponseTypes = new Set(['none', 'code', 'id_token', 'token']);
const requestObjectStrategies = new Set(['lax', 'strict']);

class Configuration {
  constructor(config) {
    authEndpointDefaults(config);

    Object.assign(this, merge({}, this.defaults, pick(config, ...Object.keys(this.defaults))));

    featuresTypeErrorCheck(this);
    clientAuthDefaults(this.clientDefaults);

    this.logDraftNotice();

    this.ensureSets();

    this.fixResponseTypes();
    this.checkWhitelistedAlgs();
    this.checkRequestMergingStrategy();
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

    this.defaults = undefined;
  }

  get defaults() {
    if (!instance(this).defaults) {
      instance(this).defaults = getDefaults();
    }

    return instance(this).defaults;
  }

  set defaults(val) {
    if (val === undefined) {
      delete instance(this).defaults;
    }
  }

  ensureSets() {
    [
      'scopes', 'subjectTypes', 'extraParams', 'acrValues',
      'tokenEndpointAuthMethods', 'introspectionEndpointAuthMethods', 'revocationEndpointAuthMethods',
    ].forEach((prop) => {
      if (!(get(this, prop) instanceof Set)) {
        if (!Array.isArray(get(this, prop))) {
          throw new TypeError(`${prop} must be an Array or Set`);
        }
        const setValue = new Set(get(this, prop));
        set(this, prop, setValue);
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
        throw new TypeError(`unsupported response type: ${type}`);
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

    if (this.scopes.has('offline_access') || this.issueRefreshToken !== this.defaults.issueRefreshToken) {
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
    Object.entries(this.claims).forEach(([key, value]) => {
      if (isPlainObject(value) || Array.isArray(value)) {
        claimDefinedScopes.push(key);
      }
    });
    claimDefinedScopes.forEach((scope) => {
      if (typeof scope === 'string' && !this.scopes.has(scope)) {
        this.scopes.add(scope);
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
    Object.entries(this.claims).forEach(([key, value]) => {
      if (Array.isArray(value)) {
        this.claims[key] = value.reduce((accumulator, claim) => {
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
    if (!this.acrValues.size) {
      delete this.claims.acr;
    }
  }

  collectClaims() {
    const claims = new Set();
    this.scopes.forEach((scope) => {
      if (scope in this.claims) {
        Object.keys(this.claims[scope]).forEach(Set.prototype.add.bind(claims));
      }
    });

    Object.entries(this.claims).forEach(([key, value]) => {
      if (value === null) claims.add(key);
    });

    this.claimsSupported = claims;
  }

  checkWhitelistedAlgs() {
    Object.entries(this.enabledJWA).forEach(([key, value]) => {
      if (!JWA[key]) {
        throw new TypeError(`invalid property enabledJWA.${key} provided`);
      }

      if (!Array.isArray(value)) {
        throw new TypeError(`invalid type for enabledJWA.${key} provided, expected Array`);
      }

      value.forEach((alg) => {
        if (!JWA[key].includes(alg)) {
          throw new TypeError(`unsupported enabledJWA.${key} algorithm provided`);
        }
      });
    });
  }

  setAlgs(prop, values, ...features) {
    if (features.length === 0 || features.every((feature) => {
      if (Array.isArray(feature)) {
        return feature.some((anyFeature) => get(this.features, anyFeature));
      }
      return get(this.features, feature);
    })) {
      this[prop] = values;
    } else {
      this[prop] = [];
    }
  }

  defaultSigAlg() {
    const whitelist = this.enabledJWA;

    this.setAlgs('idTokenSigningAlgValues', whitelist.idTokenSigningAlgValues.filter(filterHSandNone));
    this.setAlgs('idTokenEncryptionAlgValues', whitelist.idTokenEncryptionAlgValues.slice());
    this.setAlgs('idTokenEncryptionEncValues', whitelist.idTokenEncryptionEncValues.slice(), 'encryption.enabled');

    this.setAlgs('requestObjectSigningAlgValues', whitelist.requestObjectSigningAlgValues.slice(), ['requestObjects.request', 'requestObjects.requestUri']);
    this.setAlgs('requestObjectEncryptionAlgValues', whitelist.requestObjectEncryptionAlgValues.filter(RegExp.prototype.test.bind(/^(A|P|dir$)/)), 'encryption.enabled', ['requestObjects.request', 'requestObjects.requestUri']);
    this.setAlgs('requestObjectEncryptionEncValues', whitelist.requestObjectEncryptionEncValues.slice(), 'encryption.enabled', ['requestObjects.request', 'requestObjects.requestUri']);

    this.setAlgs('userinfoSigningAlgValues', whitelist.userinfoSigningAlgValues.filter(filterHSandNone), 'jwtUserinfo.enabled');
    this.setAlgs('userinfoEncryptionAlgValues', whitelist.userinfoEncryptionAlgValues.slice(), 'jwtUserinfo.enabled', 'encryption.enabled');
    this.setAlgs('userinfoEncryptionEncValues', whitelist.userinfoEncryptionEncValues.slice(), 'jwtUserinfo.enabled', 'encryption.enabled');

    this.setAlgs('introspectionSigningAlgValues', whitelist.introspectionSigningAlgValues.filter(filterHSandNone), 'jwtIntrospection.enabled');
    this.setAlgs('introspectionEncryptionAlgValues', whitelist.introspectionEncryptionAlgValues.slice(), 'jwtIntrospection.enabled', 'encryption.enabled');
    this.setAlgs('introspectionEncryptionEncValues', whitelist.introspectionEncryptionEncValues.slice(), 'jwtIntrospection.enabled', 'encryption.enabled');

    this.setAlgs('authorizationSigningAlgValues', whitelist.authorizationSigningAlgValues.filter(filterHS), 'jwtResponseModes.enabled');
    this.setAlgs('authorizationEncryptionAlgValues', whitelist.authorizationEncryptionAlgValues.slice(), 'jwtResponseModes.enabled', 'encryption.enabled');
    this.setAlgs('authorizationEncryptionEncValues', whitelist.authorizationEncryptionEncValues.slice(), 'jwtResponseModes.enabled', 'encryption.enabled');

    this.setAlgs('dPoPSigningAlgValues', whitelist.dPoPSigningAlgValues.slice(), 'dPoP.enabled');

    this.endpointAuth('token');
    this.endpointAuth('introspection');
    this.endpointAuth('revocation');
  }

  endpointAuth(endpoint) {
    this[`${endpoint}EndpointAuthSigningAlgValues`] = this.enabledJWA[`${endpoint}EndpointAuthSigningAlgValues`];

    if (!this[`${endpoint}EndpointAuthMethods`].has('client_secret_jwt')) {
      remove(this[`${endpoint}EndpointAuthSigningAlgValues`], filterHS);
    } else if (!this[`${endpoint}EndpointAuthSigningAlgValues`].find(filterHS)) {
      this[`${endpoint}EndpointAuthMethods`].delete('client_secret_jwt');
    }

    if (!this[`${endpoint}EndpointAuthMethods`].has('private_key_jwt')) {
      remove(this[`${endpoint}EndpointAuthSigningAlgValues`], filterAsymmetricSig);
    } else if (!this[`${endpoint}EndpointAuthSigningAlgValues`].find(filterAsymmetricSig)) {
      this[`${endpoint}EndpointAuthMethods`].delete('private_key_jwt');
    }

    if (!this[`${endpoint}EndpointAuthSigningAlgValues`].length) {
      this[`${endpoint}EndpointAuthSigningAlgValues`] = undefined;
    }
  }

  checkSubjectTypes() {
    if (!this.subjectTypes.size) {
      throw new TypeError('subjectTypes must not be empty');
    }

    this.subjectTypes.forEach((type) => {
      if (!['public', 'pairwise'].includes(type)) {
        throw new TypeError('only public and pairwise subjectTypes are supported');
      }
    });
  }

  checkPkceMethods() {
    if (!Array.isArray(this.pkce.methods)) {
      throw new TypeError('pkce.methods must be an array');
    }

    if (!this.pkce.methods.length) {
      throw new TypeError('pkce.methods must not be empty');
    }

    this.pkce.methods.forEach((type) => {
      if (!['plain', 'S256'].includes(type)) {
        throw new TypeError('only plain and S256 code challenge methods are supported');
      }
    });
  }

  checkDependantFeatures() {
    const { features } = this;

    if (features.pushedAuthorizationRequests.enabled && !features.requestObjects.requestUri) {
      throw new TypeError('pushedAuthorizationRequests is only available in conjuction with requestObjects.requestUri');
    }

    if (features.jwtIntrospection.enabled && !features.introspection.enabled) {
      throw new TypeError('jwtIntrospection is only available in conjuction with introspection');
    }

    if (features.jwtUserinfo.enabled && !features.userinfo.enabled) {
      throw new TypeError('jwtUserinfo is only available in conjuction with userinfo');
    }

    if (features.registrationManagement.enabled && !features.registration.enabled) {
      throw new TypeError('registrationManagement is only available in conjuction with registration');
    }

    if (
      (features.registration.enabled && features.registration.policies)
      && !features.registration.initialAccessToken
    ) {
      throw new TypeError('registration policies are only available in conjuction with adapter-backed initial access tokens');
    }
  }

  checkTTL() {
    Object.entries(this.ttl).forEach(([key, value]) => {
      let valid = false;
      switch (typeof value) {
        case 'function':
          if (value.constructor.toString() === 'function Function() { [native code] }') {
            valid = true;
          }
          break;
        case 'number':
          if (Number.isSafeInteger(value) && value > 0) {
            valid = true;
          }
          break;
        default:
      }

      if (!valid) {
        throw new TypeError(`ttl.${key} must be a positive integer or a regular function returning one`);
      }
    });
  }

  checkRequestMergingStrategy() {
    if (!requestObjectStrategies.has(this.features.requestObjects.mode)) {
      throw new TypeError(`'mode' must be ${formatters.formatList([...requestObjectStrategies], { type: 'disjunction' })}`);
    }
  }

  checkAuthMethods() {
    const authMethods = new Set([
      'none',
      'client_secret_basic',
      'client_secret_jwt',
      'client_secret_post',
      'private_key_jwt',
    ]);

    if (this.features.mTLS.enabled && this.features.mTLS.tlsClientAuth) {
      authMethods.add('tls_client_auth');
    }

    if (this.features.mTLS.enabled && this.features.mTLS.selfSignedTlsClientAuth) {
      authMethods.add('self_signed_tls_client_auth');
    }

    ['token', 'introspection', 'revocation'].forEach((endpoint) => {
      if (this[`${endpoint}EndpointAuthMethods`]) {
        this[`${endpoint}EndpointAuthMethods`].forEach((method) => {
          if (!authMethods.has(method)) {
            throw new TypeError(`only supported ${endpoint}EndpointAuthMethods are ${formatters.formatList([...authMethods])}`);
          }
        });
      }
    });
  }

  checkDeviceFlow() {
    if (this.features.deviceFlow.enabled) {
      if (this.features.deviceFlow.charset !== undefined) {
        if (!['base-20', 'digits'].includes(this.features.deviceFlow.charset)) {
          throw new TypeError('only supported charsets are "base-20" and "digits"');
        }
      }
      if (!/^[-* ]*$/.test(this.features.deviceFlow.mask)) {
        throw new TypeError('mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters');
      }
    }
  }

  logDraftNotice() {
    const ENABLED_DRAFTS = new Set();
    let throwDraft = false;

    Object.entries(this.features).forEach(([flag, { enabled, ack }]) => {
      const { features: recognizedFeatures } = getDefaults();
      if (!(flag in recognizedFeatures)) {
        throw new TypeError(`Unknown feature configuration: ${flag}`);
      }

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

      if (enabled && !draft && ack !== undefined) {
        throw new TypeError(`${flag} feature is now stable, the ack ${ack} is no longer valid. Check the stable feature's configuration for any breaking changes.`);
      }
    });

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
      attention.info(`You may disable this notice and these potentially breaking updates by acknowledging the current draft version. See ${docs('features')}`);

      if (throwDraft) {
        throw new TypeError('An unacknowledged version of a draft feature is included in this oidc-provider version.');
      }
    }
  }
}

Configuration.prototype.postLogoutSuccessSourceDeprecationNotice = deprecate(
  /* istanbul ignore next */
  () => {},
  `postLogoutSuccessSourceDeprecationNotice is deprecated, use features.rpInitiatedLogout.postLogoutSuccessSourceDeprecationNotice for configuring it instead, see ${docs('featuresrpinitiatedlogout')}`,
);

Configuration.prototype.logoutSourceDeprecationNotice = deprecate(
  /* istanbul ignore next */
  () => {},
  `logoutSourceDeprecationNotice is deprecated, use features.rpInitiatedLogout.logoutSourceDeprecationNotice for configuring it instead, see ${docs('featuresrpinitiatedlogout')}`,
);

module.exports = Configuration;
