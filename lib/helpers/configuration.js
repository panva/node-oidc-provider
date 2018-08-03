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

    if (this.subjectTypes.includes('pairwise') && !this.pairwiseSalt) {
      throw new Error('pairwiseSalt must be configured when pairwise subjectType is to be supported');
    }

    if (!this.features.sessionManagement) {
      if (this.features.backchannelLogout) {
        throw new Error('backchannelLogout is only available in conjuction with sessionManagement');
      }
      if (this.features.frontchannelLogout) {
        throw new Error('frontchannelLogout is only available in conjuction with sessionManagement');
      }
    }

    if (!this.features.introspection) {
      if (this.features.jwtIntrospection) {
        throw new Error('jwtIntrospection is only available in conjuction with introspection');
      }
    }

    if (this.features.registrationManagement && !this.features.registration) {
      throw new Error('registrationManagement is only available in conjuction with registration');
    }

    if (this.features.deviceCode) {
      if (this.features.deviceCode.charset !== undefined) {
        if (!['base-20', 'digits'].includes(this.features.deviceCode.charset)) {
          throw new Error('only supported charsets are "base-20" and "digits"');
        }
      }
      if (this.features.deviceCode.mask !== undefined) {
        if (!/^[-* ]*$/.exec(this.features.deviceCode.mask)) {
          throw new Error('mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters');
        }
      }
    }

    /* eslint-disable no-restricted-syntax */
    if (process.env.NODE_ENV !== 'test') {
      for (const flag in this.features) {
        if (this.features[flag] && !STABLE_FLAGS.includes(flag)) {
          attention.info(`a draft/experimental feature (${flag}) enabled, future updates to \
this feature will be released as MINOR releases`);
        }
      }
    }
    /* eslint-enable */
  }
}

module.exports = function getConfiguration(config) {
  return new Configuration(config);
};
