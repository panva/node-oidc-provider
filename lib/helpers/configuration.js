'use strict';

const MemoryAdapter = require('../adapters/memory_adapter');
const ConfigurationSchema = require('./configuration_schema');

const STABLE_FLAGS = [
  'claimsParameter',
  'clientCredentials',
  'discovery',
  'encryption',
  'introspection',
  'refreshToken',
  'registration',
  'request',
  'requestUri',
  'revocation',
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

    /* eslint-disable no-restricted-syntax, no-console */
    if (process.env.NODE_ENV !== 'test') {
      for (const flag in this.features) {
        if (this.features[flag] && STABLE_FLAGS.indexOf(flag) === -1) {
          console.warn(`WARNING: a draft/experimental feature (${flag}) enabled, future updates to \
this feature will be released as MINOR releases`);
        }
      }
    }
    /* eslint-enable */

    if (!this.adapter) this.adapter = MemoryAdapter;
    if (!this.findById) {
      this.findById = id => Promise.resolve({
        accountId: id,
        claims() { return { sub: id }; },
      });
    }
  }
}

module.exports = function getConfiguration(config) {
  return new Configuration(config);
};
