const attention = require('./attention');
const ConfigurationSchema = require('./configuration_schema');

const STABLE_FLAGS = [
  'oauthNativeApps',
  'claimsParameter',
  'clientCredentials',
  'conformIdTokenClaims',
  'discovery',
  'encryption',
  'introspection',
  'alwaysIssueRefresh',
  'registration',
  'request',
  'requestUri',
  'revocation',
  'pkce',
  'devInteractions',
];

class Configuration {
  constructor(config = {}) {
    const schema = new ConfigurationSchema(config);
    Object.assign(this, schema);

    if (!Array.isArray(this.subjectTypes)) {
      throw new Error('subjectTypes must be an array');
    }

    if (!this.subjectTypes.length) {
      throw new Error('subjectTypes must not be empty');
    }

    this.subjectTypes.forEach((type) => {
      if (!['public', 'pairwise'].includes(type)) {
        throw new Error('only public and pairwise subjectTypes are supported');
      }
    });

    if (this.features.pkce && this.features.pkce.supportedMethods) {
      if (!Array.isArray(this.features.pkce.supportedMethods)) {
        throw new Error('supportedMethods must be an array');
      }

      if (!this.features.pkce.supportedMethods.length) {
        throw new Error('supportedMethods must not be empty');
      }

      this.features.pkce.supportedMethods.forEach((type) => {
        if (!['plain', 'S256'].includes(type)) {
          throw new Error('only plain and S256 code challenge methods are supported');
        }
      });
    }

    if (!this.features.introspection) {
      if (this.features.jwtIntrospection) {
        throw new Error('jwtIntrospection is only available in conjuction with introspection');
      }
    }

    if (this.features.registrationManagement && !this.features.registration) {
      throw new Error('registrationManagement is only available in conjuction with registration');
    }

    if (
      (this.features.registration && this.features.registration.policies)
      && !this.features.registration.initialAccessToken
    ) {
      throw new Error('registration policies are only available in conjuction with adapter-backed initial access tokens');
    }

    if (this.features.deviceFlow) {
      if (this.features.deviceFlow.charset !== undefined) {
        if (!['base-20', 'digits'].includes(this.features.deviceFlow.charset)) {
          throw new Error('only supported charsets are "base-20" and "digits"');
        }
      }
      if (this.features.deviceFlow.mask !== undefined) {
        if (!/^[-* ]*$/.test(this.features.deviceFlow.mask)) {
          throw new Error('mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters');
        }
      }
    }

    /* istanbul ignore if */
    if (process.env.NODE_ENV !== 'test') {
      Object.entries(this.features).forEach(([flag, value]) => {
        if (value && !STABLE_FLAGS.includes(flag)) {
          attention.info(`a draft/experimental feature (${flag}) enabled, future updates to \
this feature will be released as MINOR releases`);
        }
      });

      /* eslint-disable no-restricted-syntax */
      for (const endpoint of ['token', 'introspection', 'revocation']) {
        if (this[`${endpoint}EndpointAuthMethods`].includes('tls_client_auth')) {
          attention.info('a draft/experimental feature (tls_client_auth) enabled, future updates to this feature will be released as MINOR releases');
          break;
        }
      }
      /* eslint-enable */
    }
  }
}

module.exports = function getConfiguration(config) {
  return new Configuration(config);
};
