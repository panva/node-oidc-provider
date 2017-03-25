'use strict';

const ConfigurationSchema = require('./configuration_schema');

const STABLE_FLAGS = [
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
  constructor(config) {
    const schema = new ConfigurationSchema(config);
    Object.assign(this, schema);

    this.subjectTypes.forEach((type) => {
      /* istanbul ignore if */
      if (['public', 'pairwise'].indexOf(type) === -1) {
        throw new Error('only public and pairwise subjectTypes are supported');
      }
    });

    if (this.subjectTypes.indexOf('pairwise') !== -1 && !this.pairwiseSalt) {
      throw new Error(
        'pairwiseSalt must be configured when pairwise subjectType is to be supported');
    }

    if (this.features.backchannelLogout && !this.features.sessionManagement) {
      throw new Error('backchannelLogout is only available in conjuction with sessionManagement');
    }

    if (this.features.registrationManagement && !this.features.registration) {
      throw new Error('registrationManagement is only available in conjuction with registration');
    }

    if (this.features.oauthNativeApps && !this.features.pkce) {
      this.features.pkce = { skipClientAuth: true };
    }

    /* eslint-disable no-restricted-syntax, no-console */
    if (process.env.NODE_ENV !== 'test') {
      for (const flag in this.features) {
        if (this.features[flag] && STABLE_FLAGS.indexOf(flag) === -1) {
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
