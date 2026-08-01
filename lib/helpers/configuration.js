import { JWA } from '../consts/index.js';
import isPlainObject from './_/is_plain_object.js';
import merge from './_/merge.js';
import pick from './_/pick.js';
import remove from './_/remove.js';
import set from './_/set.js';
import * as attention from './attention.js';
import getDefaults from './defaults.js';
import { InvalidAuthorizationDetails } from './errors.js';
import { EXPERIMENTS, STABLE } from './features.js';
import * as formatters from './formatters.js';

function featuresTypeErrorCheck({ features }) {
  for (const value of Object.values(features)) {
    if (typeof value === 'boolean') {
      throw new TypeError('Features are not enabled/disabled with a boolean value. See the documentation for more details.');
    }
  }
}

function checkKeyAttestationsRequired(proofTypeConfig, prefix) {
  const { key_attestations_required: keyAttestationsRequired } = proofTypeConfig;
  if (keyAttestationsRequired !== undefined) {
    if (!isPlainObject(keyAttestationsRequired)) {
      throw new TypeError(
        `${prefix}.key_attestations_required must be a plain object`,
      );
    }

    for (const claim of ['key_storage', 'user_authentication']) {
      const values = keyAttestationsRequired[claim];
      if (values !== undefined) {
        if (
          !Array.isArray(values)
          || values.length === 0
          || !values.every((v) => typeof v === 'string' && v.length > 0)
        ) {
          throw new TypeError(
            `${prefix}.key_attestations_required.${claim} must be a non-empty array of non-empty strings`,
          );
        }
      }
    }
  }
}

function filterHS(alg) {
  return alg.startsWith('HS');
}

function filterAsymmetricSig(alg) {
  switch (alg.slice(0, 2)) {
    case 'ML': // ML-DSA-*, ML-KEM-*
    case 'RS': // RS\d{3}, RSA-OAEP
    case 'PS': // PS\d{3}
    case 'ES': // ECDSA
    case 'EC': // ECDH
    case 'Ed': // Ed*
    case 'X2': // X25519
    case 'X4': // X448
      return true;
    default:
      return false;
  }
}

const supportedResponseTypes = new Set(['none', 'code', 'id_token', 'token']);
const fapiProfiles = new Set(['1.0 Final', '2.0']);

function cloneConfiguration(value) {
  if (Array.isArray(value)) {
    return value.map(cloneConfiguration);
  }

  if (value instanceof Set) {
    return new Set([...value].map(cloneConfiguration));
  }

  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, cloneConfiguration(entry)]),
    );
  }

  return value;
}

function validateOpenid4vciClaims(claims) {
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new InvalidAuthorizationDetails("'claims' must be a non-empty array when provided");
  }

  for (const claim of claims) {
    if (!isPlainObject(claim)) {
      throw new InvalidAuthorizationDetails('claims description entries must be JSON objects');
    }

    if (!Array.isArray(claim.path) || claim.path.length === 0) {
      throw new InvalidAuthorizationDetails('claims description path must be a non-empty array');
    }

    for (const component of claim.path) {
      const valid = (
        (typeof component === 'string' && component.length)
        || component === null
        || (Number.isInteger(component) && component >= 0)
      );

      if (!valid) {
        throw new InvalidAuthorizationDetails('claims description path entries must be non-empty strings, null, or non-negative integers');
      }
    }

    if ('mandatory' in claim && typeof claim.mandatory !== 'boolean') {
      throw new InvalidAuthorizationDetails('claims description mandatory must be a boolean when provided');
    }
  }
}

class Configuration {
  #defaults = getDefaults();

  constructor(config) {
    const input = cloneConfiguration(pick(config, ...Object.keys(this.#defaults)));
    Object.assign(this, merge({}, this.#defaults, input));

    featuresTypeErrorCheck(this);

    this.logDraftNotice();

    this.registerExtraParamsValidations();
    this.ensureSets();

    this.checkResponseTypes();
    this.checkAllowedJWA();
    this.checkFapiProfile();
    this.collectScopes();
    this.collectPrompts();
    this.unpackArrayClaims();
    this.ensureOpenIdSub();
    this.removeAcrIfEmpty();
    this.collectClaims();
    this.defaultSigAlg();
    this.collectGrantTypes();
    this.checkSubjectTypes();
    this.checkDependantFeatures();
    this.checkDeviceFlow();
    this.checkAttestClientAuth();
    this.checkAuthMethods();
    this.checkTTL();
    this.checkCibaDeliveryModes();
    this.checkRichAuthorizationRequests();
    this.checkOpenid4vci();
    this.checkPostMethods();
    this.checkFetchResponseBodyLimits();

    delete this.cookies.long.maxAge;
    delete this.cookies.long.expires;
    delete this.cookies.short.maxAge;
    delete this.cookies.short.expires;

    // release #defaults
    this.#defaults = undefined;
  }

  checkRichAuthorizationRequests() {
    if (this.features.richAuthorizationRequests.enabled) {
      const { richAuthorizationRequests, openid4vci } = this.features;

      if (!isPlainObject(richAuthorizationRequests.types)) {
        throw new TypeError('features.richAuthorizationRequests.types must be an object');
      }

      if (openid4vci.enabled && !Object.hasOwn(richAuthorizationRequests.types, 'openid_credential')) {
        richAuthorizationRequests.types.openid_credential = {
          validate(_ctx, detail) {
            if (typeof detail.credential_configuration_id !== 'string' || !detail.credential_configuration_id.length) {
              throw new InvalidAuthorizationDetails("'credential_configuration_id' must be a non-empty string");
            }

            if ('claims' in detail) {
              validateOpenid4vciClaims(detail.claims);
            }
          },
        };
      }

      for (const [k, v] of Object.entries(richAuthorizationRequests.types)) {
        if (!isPlainObject(v)) {
          throw new TypeError('features.richAuthorizationRequests.types attribute values must be objects');
        }
        if (typeof v.validate !== 'function' || !['Function', 'AsyncFunction'].includes(v.validate.constructor.name)) {
          throw new TypeError(`features.richAuthorizationRequests.types['${k}'].validate must be a function`);
        }
      }
    }
  }

  checkOpenid4vci() {
    const { openid4vci } = this.features;

    if (!openid4vci.enabled) {
      return;
    }

    if (!isPlainObject(openid4vci.metadata)) {
      throw new TypeError('features.openid4vci.metadata must be an object');
    }

    if (typeof openid4vci.preAuthorizedCodeGrant !== 'boolean') {
      throw new TypeError('features.openid4vci.preAuthorizedCodeGrant must be a boolean');
    }

    const batchCredentialIssuance = openid4vci.metadata.batch_credential_issuance;
    if (batchCredentialIssuance !== undefined) {
      if (!isPlainObject(batchCredentialIssuance)) {
        throw new TypeError('features.openid4vci.metadata.batch_credential_issuance must be an object');
      }

      if (
        !Number.isSafeInteger(batchCredentialIssuance.batch_size)
        || batchCredentialIssuance.batch_size < 2
      ) {
        throw new TypeError('features.openid4vci.metadata.batch_credential_issuance.batch_size must be an integer greater than or equal to 2');
      }
    }

    if (
      !isPlainObject(openid4vci.credentialConfigurationsSupported)
      || !Object.keys(openid4vci.credentialConfigurationsSupported).length
    ) {
      throw new TypeError('features.openid4vci.credentialConfigurationsSupported must be a non-empty object');
    }

    for (
      const [credentialConfigurationId, credentialConfiguration]
      of Object.entries(openid4vci.credentialConfigurationsSupported)
    ) {
      if (!isPlainObject(credentialConfiguration)) {
        throw new TypeError(`features.openid4vci.credentialConfigurationsSupported['${credentialConfigurationId}'] must be an object`);
      }

      const ccPrefix = `features.openid4vci.credentialConfigurationsSupported['${credentialConfigurationId}']`;

      if (typeof credentialConfiguration.format !== 'string' || !credentialConfiguration.format.length) {
        throw new TypeError(`${ccPrefix}.format must be a non-empty string`);
      }

      const proofTypesSupported = credentialConfiguration.proof_types_supported;
      if (isPlainObject(proofTypesSupported)) {
        const supportedProofTypes = new Set(['jwt', 'attestation']);
        const unsupportedProofTypes = Object.keys(proofTypesSupported)
          .filter((t) => !supportedProofTypes.has(t));
        if (unsupportedProofTypes.length) {
          throw new TypeError(
            `${ccPrefix}.proof_types_supported contains unsupported proof type(s): ${unsupportedProofTypes.join(', ')}`,
          );
        }

        if (Object.hasOwn(proofTypesSupported, 'jwt')) {
          const cryptographicBindingMethodsSupported = credentialConfiguration
            .cryptographic_binding_methods_supported;

          if (
            !Array.isArray(cryptographicBindingMethodsSupported)
            || !cryptographicBindingMethodsSupported.includes('jwk')
          ) {
            throw new TypeError(
              `${ccPrefix}.cryptographic_binding_methods_supported must include 'jwk' when jwt proofs are supported`,
            );
          }

          checkKeyAttestationsRequired(proofTypesSupported.jwt, `${ccPrefix}.proof_types_supported.jwt`);
        }

        if (Object.hasOwn(proofTypesSupported, 'attestation')) {
          checkKeyAttestationsRequired(proofTypesSupported.attestation, `${ccPrefix}.proof_types_supported.attestation`);
        }
      }

      // Only `jwk` cryptographic binding method is implemented.
      const cryptographicBindingMethodsSupported = credentialConfiguration
        .cryptographic_binding_methods_supported;
      if (Array.isArray(cryptographicBindingMethodsSupported)) {
        const unsupportedMethods = cryptographicBindingMethodsSupported.filter((m) => m !== 'jwk');
        if (unsupportedMethods.length) {
          throw new TypeError(
            `${ccPrefix}.cryptographic_binding_methods_supported contains unsupported method(s): ${unsupportedMethods.join(', ')}`,
          );
        }
      }

      // Credential response encryption is not implemented.
      if (credentialConfiguration.credential_response_encryption !== undefined) {
        throw new TypeError(
          `${ccPrefix}.credential_response_encryption is not supported`,
        );
      }
    }

    // Credential response encryption metadata is not implemented.
    if (openid4vci.metadata.credential_response_encryption !== undefined) {
      throw new TypeError(
        'features.openid4vci.metadata.credential_response_encryption is not supported',
      );
    }

    const policy = openid4vci.credentialConfigurationPolicy;
    if (typeof policy !== 'function' || !['Function', 'AsyncFunction'].includes(policy.constructor.name)) {
      throw new TypeError('features.openid4vci.credentialConfigurationPolicy must be a function');
    }

    const { issueCredential } = openid4vci;
    if (typeof issueCredential !== 'function' || !['Function', 'AsyncFunction'].includes(issueCredential.constructor.name)) {
      throw new TypeError('features.openid4vci.issueCredential must be a function');
    }
  }

  registerExtraParamsValidations() {
    if (!isPlainObject(this.extraParams)) {
      return;
    }

    this.extraParamsValidations = Object.entries(this.extraParams).map(([key, value]) => {
      if (value == null) {
        return undefined;
      }

      if (typeof value !== 'function' || !['Function', 'AsyncFunction'].includes(value.constructor.name)) {
        throw new TypeError(`invalid extraParams.${key} type, it must be a function, null, or undefined`);
      }

      return [key, value];
    }).filter(Boolean);

    this.extraParams = new Set(Object.keys(this.extraParams));
  }

  ensureSets() {
    for (const [obj, props] of [
      [this, ['scopes', 'subjectTypes', 'extraParams', 'acrValues', 'clientAuthMethods']],
      [this.features.ciba, ['deliveryModes']],
    ]) {
      for (const prop of props) {
        if (!(obj[prop] instanceof Set)) {
          if (!Array.isArray(obj[prop])) {
            throw new TypeError(`${prop} must be an Array or Set`);
          }
          const setValue = new Set(obj[prop]);
          set(obj, prop, setValue);
        }
      }
    }
  }

  checkResponseTypes() {
    const types = new Set();

    this.responseTypes.forEach((type) => {
      const parsed = new Set(type.split(' '));

      if (
        (parsed.has('none') && parsed.size !== 1)
        || (parsed.has('token') && parsed.size === 1)
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

    if (this.scopes.has('offline_access') || this.issueRefreshToken !== this.#defaults.issueRefreshToken) {
      this.grantTypes.add('refresh_token');
    }

    if (this.features.clientCredentials.enabled) {
      this.grantTypes.add('client_credentials');
    }

    if (this.features.deviceFlow.enabled) {
      this.grantTypes.add('urn:ietf:params:oauth:grant-type:device_code');
    }

    if (this.features.ciba.enabled) {
      this.grantTypes.add('urn:openid:params:grant-type:ciba');
    }

    if (this.features.openid4vci.enabled && this.features.openid4vci.preAuthorizedCodeGrant) {
      this.grantTypes.add('urn:ietf:params:oauth:grant-type:pre-authorized_code');
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

  checkAllowedJWA() {
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
    if (features.length === 0 || features.every((enabled) => !!enabled)) {
      this[prop] = values;
    } else {
      this[prop] = [];
    }
  }

  defaultSigAlg() {
    const allowList = this.enabledJWA;

    const enabled = {
      encryption: this.features.encryption.enabled,
      requestObjects: this.features.requestObjects.enabled,
      jwtUserinfo: this.features.jwtUserinfo.enabled,
      jwtIntrospection: this.features.jwtIntrospection.enabled,
      jwtResponseModes: this.features.jwtResponseModes.enabled,
      dPoP: this.features.dPoP.enabled,
      attestClientAuth: this.features.attestClientAuth.enabled,
    };

    this.setAlgs('idTokenSigningAlgValues', allowList.idTokenSigningAlgValues.filter(filterHS));
    this.setAlgs('idTokenEncryptionAlgValues', allowList.idTokenEncryptionAlgValues.slice());
    this.setAlgs('idTokenEncryptionEncValues', allowList.idTokenEncryptionEncValues.slice(), enabled.encryption);

    this.setAlgs('requestObjectSigningAlgValues', allowList.requestObjectSigningAlgValues.slice(), enabled.requestObjects);
    this.setAlgs('requestObjectEncryptionAlgValues', allowList.requestObjectEncryptionAlgValues.filter(RegExp.prototype.test.bind(/^(A|dir$)/)), enabled.encryption, enabled.requestObjects);
    this.setAlgs('requestObjectEncryptionEncValues', allowList.requestObjectEncryptionEncValues.slice(), enabled.encryption, enabled.requestObjects);

    this.setAlgs('userinfoSigningAlgValues', allowList.userinfoSigningAlgValues.filter(filterHS), enabled.jwtUserinfo);
    this.setAlgs('userinfoEncryptionAlgValues', allowList.userinfoEncryptionAlgValues.slice(), enabled.jwtUserinfo, enabled.encryption);
    this.setAlgs('userinfoEncryptionEncValues', allowList.userinfoEncryptionEncValues.slice(), enabled.jwtUserinfo, enabled.encryption);

    this.setAlgs('introspectionSigningAlgValues', allowList.introspectionSigningAlgValues.filter(filterHS), enabled.jwtIntrospection);
    this.setAlgs('introspectionEncryptionAlgValues', allowList.introspectionEncryptionAlgValues.slice(), enabled.jwtIntrospection, enabled.encryption);
    this.setAlgs('introspectionEncryptionEncValues', allowList.introspectionEncryptionEncValues.slice(), enabled.jwtIntrospection, enabled.encryption);

    this.setAlgs('authorizationSigningAlgValues', allowList.authorizationSigningAlgValues.filter(filterHS), enabled.jwtResponseModes);
    this.setAlgs('authorizationEncryptionAlgValues', allowList.authorizationEncryptionAlgValues.slice(), enabled.jwtResponseModes, enabled.encryption);
    this.setAlgs('authorizationEncryptionEncValues', allowList.authorizationEncryptionEncValues.slice(), enabled.jwtResponseModes, enabled.encryption);

    this.setAlgs('dPoPSigningAlgValues', allowList.dPoPSigningAlgValues.slice(), enabled.dPoP);
    this.setAlgs('attestSigningAlgValues', allowList.attestSigningAlgValues.slice(), enabled.attestClientAuth);

    this.clientAuthSigningAlgValues = this.enabledJWA.clientAuthSigningAlgValues;

    if (!this.clientAuthMethods.has('client_secret_jwt')) {
      remove(this.clientAuthSigningAlgValues, filterHS);
    } else if (!this.clientAuthSigningAlgValues.find(filterHS)) {
      this.clientAuthMethods.delete('client_secret_jwt');
    }

    if (!this.clientAuthMethods.has('private_key_jwt')) {
      remove(this.clientAuthSigningAlgValues, filterAsymmetricSig);
    } else if (!this.clientAuthSigningAlgValues.find(filterAsymmetricSig)) {
      this.clientAuthMethods.delete('private_key_jwt');
    }

    if (!this.clientAuthSigningAlgValues.length) {
      this.clientAuthSigningAlgValues = undefined;
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

  checkCibaDeliveryModes() {
    const modes = this.features.ciba.deliveryModes;
    if (!modes.size) {
      throw new TypeError('features.ciba.deliveryModes must not be empty');
    }

    for (const mode of modes) {
      if (!['ping', 'poll'].includes(mode)) {
        throw new TypeError('only poll and ping CIBA delivery modes are supported');
      }
    }
  }

  checkDependantFeatures() {
    const { features } = this;

    if (features.jwtIntrospection.enabled && !features.introspection.enabled) {
      throw new TypeError('jwtIntrospection is only available in conjunction with introspection');
    }

    if (features.jwtUserinfo.enabled && !features.userinfo.enabled) {
      throw new TypeError('jwtUserinfo is only available in conjunction with userinfo');
    }

    if (features.registrationManagement.enabled && !features.registration.enabled) {
      throw new TypeError('registrationManagement is only available in conjunction with registration');
    }

    if (
      (features.registration.enabled && features.registration.policies)
      && !features.registration.initialAccessToken
    ) {
      throw new TypeError('registration policies are only available in conjunction with adapter-backed initial access tokens');
    }

    if (features.richAuthorizationRequests.enabled && !features.resourceIndicators.enabled) {
      throw new TypeError('richAuthorizationRequests is only available in conjunction with enabled resourceIndicators');
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
        case 'undefined': // does not expire
          valid = true;
          break;
        default:
      }

      if (!valid) {
        throw new TypeError(`ttl.${key} must be a positive integer or a regular function returning one`);
      }
    });
  }

  checkFapiProfile() {
    if (!this.features.fapi.enabled) {
      this.features.fapi.profile = () => undefined;
    } else if (typeof this.features.fapi.profile === 'function') {
      const helper = this.features.fapi.profile;
      this.features.fapi.profile = (...args) => {
        const profile = helper(...args);
        if (profile && !fapiProfiles.has(profile)) {
          throw new TypeError(`'profile' must be ${formatters.formatList([...fapiProfiles], { type: 'disjunction' })}`);
        }
        return profile || undefined;
      };
    } else if (!fapiProfiles.has(this.features.fapi.profile)) {
      throw new TypeError(`'profile' must be ${formatters.formatList([...fapiProfiles], { type: 'disjunction' })}`);
    } else {
      const value = this.features.fapi.profile;
      this.features.fapi.profile = () => value;
    }
  }

  checkPostMethods() {
    if (this.enableHttpPostMethods && this.cookies.long.sameSite?.toLowerCase() !== 'none') {
      throw new TypeError('HTTP POST Method support requires that cookies.long.sameSite is set to none');
    }
  }

  checkAttestClientAuth() {
    const { additionalSecuritySignal } = this.features.attestClientAuth;

    if (
      additionalSecuritySignal !== false
      && additionalSecuritySignal !== 'optional'
      && additionalSecuritySignal !== 'required'
    ) {
      throw new TypeError('features.attestClientAuth.additionalSecuritySignal must be false, optional, or required');
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

    if (this.features.attestClientAuth.enabled) {
      authMethods.add('attest_jwt_client_auth');
    }

    if (this.clientAuthMethods) {
      this.clientAuthMethods.forEach((method) => {
        if (!authMethods.has(method)) {
          throw new TypeError(`only supported clientAuthMethods are ${formatters.formatList([...authMethods])}`);
        }
      });
    }
  }

  checkFetchResponseBodyLimits() {
    const { fetchResponseBodyLimits } = this;
    if (!isPlainObject(fetchResponseBodyLimits)) {
      throw new TypeError('fetchResponseBodyLimits must be a plain object');
    }
    for (const [key, value] of Object.entries(fetchResponseBodyLimits)) {
      if (typeof value !== 'number' || (!Number.isSafeInteger(value) && value !== Infinity) || value < 0) {
        throw new TypeError(`fetchResponseBodyLimits.${JSON.stringify(key)} must be a non-negative safe integer or Infinity`);
      }
    }
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
    const ENABLED_EXPERIMENTS = new Set();
    let throwExperiment = false;

    Object.entries(this.features).forEach(([flag, { enabled, ack }]) => {
      const { features: recognizedFeatures } = getDefaults();
      if (!(flag in recognizedFeatures)) {
        throw new TypeError(`Unknown feature configuration: ${flag}`);
      }

      const experimental = EXPERIMENTS.get(flag);
      if (
        experimental
        && enabled && !STABLE.has(flag)
        && (
          Array.isArray(experimental.version)
            ? !experimental.version.includes(ack) : ack !== experimental.version
        )
      ) {
        if (typeof ack !== 'undefined') {
          throwExperiment = true;
        }
        ENABLED_EXPERIMENTS.add(flag);
      }

      if (enabled && !experimental && ack !== undefined) {
        throw new TypeError(`${flag} feature is now stable, the ack ${ack} is no longer valid. Check the stable feature's configuration for any breaking changes.`);
      }
    });

    if (ENABLED_EXPERIMENTS.size) {
      attention.info('The following experimental features are enabled and their implemented version not acknowledged');
      ENABLED_EXPERIMENTS.forEach((experimental) => {
        const { name } = EXPERIMENTS.get(experimental);
        let { version } = EXPERIMENTS.get(experimental);

        if (Array.isArray(version)) {
          version = version[version.length - 1];
        }

        attention.info(`  - ${name} (Acknowledging this feature's implemented version can be done with the value '${version}')`);
      });
      attention.info('Breaking changes between experimental feature updates may occur and these will be published as MINOR semver oidc-provider updates.');
      attention.info("You may disable this notice and be warned when breaking updates occur by acknowledging the current experiment's version. See the documentation for more details.");

      if (throwExperiment) {
        throw new TypeError('An unacknowledged version of an experimental feature is included in this oidc-provider version.');
      }
    }
  }
}

export default Configuration;
