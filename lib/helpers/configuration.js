const ConfigurationSchema = require('./configuration_schema');

const STABLE_FLAGS = [
  'oauthNativeApps',
  'claimsParameter',
  'clientCredentials',
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

    this.subjectTypes.forEach((type) => {
      /* istanbul ignore if */
      if (!['public', 'pairwise'].includes(type)) {
        throw new Error('only public and pairwise subjectTypes are supported');
      }
    });

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


    if (this.features.registrationManagement && !this.features.registration) {
      throw new Error('registrationManagement is only available in conjuction with registration');
    }

    /* eslint-disable no-restricted-syntax, no-console */
    if (process.env.NODE_ENV !== 'test') {
      for (const flag in this.features) {
        if (this.features[flag] && !STABLE_FLAGS.includes(flag)) {
          console.info(`NOTICE: a draft/experimental feature (${flag}) enabled, future updates to \
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
