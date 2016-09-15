'use strict';

const _ = require('lodash');
const MemoryAdapter = require('../adapters/memory_adapter');
const ConfigurationSchema = require('./configuration_schema');
const jose = require('node-jose');

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

function registerKey(key) {
  try {
    key.toPEM(true);
  } catch (err) {
    throw new Error('only private RSA or EC keys should be part of config.keystore');
  }

  if (this.features.encryption) {
    const encryptionAlgs = key.algorithms('wrap');
    [
      // 'idTokenEncryptionAlgValues',
      'requestObjectEncryptionAlgValues',
      // 'userinfoEncryptionAlgValues',
    ].forEach((prop) => {
      this[prop] = _.union(this[prop], encryptionAlgs);
    });
  }

  const signingAlgs = key.algorithms('sign');
  [
    'idTokenSigningAlgValues',
    // 'requestObjectSigningAlgValues' if signed use private sig of clients (or their secret)
    // 'tokenEndpointAuthSigningAlgValues' if used then with client keys or their secret
    'userinfoSigningAlgValues',
  ].forEach((prop) => {
    this[prop] = _.union(this[prop], signingAlgs);
  });
}

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

    if (this.keystore !== undefined && this.keystore !== 'development') {
      if (!jose.JWK.isKeyStore(this.keystore)) {
        throw new Error('config.keystore must be a jose.JWK.KeyStore instance');
      }
      const mustHave = this.keystore.get({ kty: 'RSA', alg: 'RS256', use: 'sig' });
      if (!mustHave) throw new Error('RS256 signing must be supported but no viable key is found');

      this.keystore.all().forEach(registerKey.bind(this));
    } else if (this.keystore === 'development') {
      /* eslint-disable max-len, no-console */
      console.warn('WARNING: a pre-configured set of development certificates is used, use configuration.keystore to provide your own');
      this.keystore = jose.JWK.createKeyStore();
      this.keystore.add({
        d: 'VEZOsY07JTFzGTqv6cC2Y32vsfChind2I_TTuvV225_-0zrSej3XLRg8iE_u0-3GSgiGi4WImmTwmEgLo4Qp3uEcxCYbt4NMJC7fwT2i3dfRZjtZ4yJwFl0SIj8TgfQ8ptwZbFZUlcHGXZIr4nL8GXyQT0CK8wy4COfmymHrrUoyfZA154ql_OsoiupSUCRcKVvZj2JHL2KILsq_sh_l7g2dqAN8D7jYfJ58MkqlknBMa2-zi5I0-1JUOwztVNml_zGrp27UbEU60RqV3GHjoqwI6m01U7K0a8Q_SQAKYGqgepbAYOA-P4_TLl5KC4-WWBZu_rVfwgSENwWNEhw8oQ',
        dp: 'E1Y-SN4bQqX7kP-bNgZ_gEv-pixJ5F_EGocHKfS56jtzRqQdTurrk4jIVpI-ZITA88lWAHxjD-OaoJUh9Jupd_lwD5Si80PyVxOMI2xaGQiF0lbKJfD38Sh8frRpgelZVaK_gm834B6SLfxKdNsP04DsJqGKktODF_fZeaGFPH0',
        dq: 'F90JPxevQYOlAgEH0TUt1-3_hyxY6cfPRU2HQBaahyWrtCWpaOzenKZnvGFZdg-BuLVKjCchq3G_70OLE-XDP_ol0UTJmDTT-WyuJQdEMpt_WFF9yJGoeIu8yohfeLatU-67ukjghJ0s9CBzNE_LrGEV6Cup3FXywpSYZAV3iqc',
        e: 'AQAB',
        kty: 'RSA',
        n: 'xwQ72P9z9OYshiQ-ntDYaPnnfwG6u9JAdLMZ5o0dmjlcyrvwQRdoFIKPnO65Q8mh6F_LDSxjxa2Yzo_wdjhbPZLjfUJXgCzm54cClXzT5twzo7lzoAfaJlkTsoZc2HFWqmcri0BuzmTFLZx2Q7wYBm0pXHmQKF0V-C1O6NWfd4mfBhbM-I1tHYSpAMgarSm22WDMDx-WWI7TEzy2QhaBVaENW9BKaKkJklocAZCxk18WhR0fckIGiWiSM5FcU1PY2jfGsTmX505Ub7P5Dz75Ygqrutd5tFrcqyPAtPTFDk8X1InxkkUwpP3nFU5o50DGhwQolGYKPGtQ-ZtmbOfcWQ',
        p: '5wC6nY6Ev5FqcLPCqn9fC6R9KUuBej6NaAVOKW7GXiOJAq2WrileGKfMc9kIny20zW3uWkRLm-O-3Yzze1zFpxmqvsvCxZ5ERVZ6leiNXSu3tez71ZZwp0O9gys4knjrI-9w46l_vFuRtjL6XEeFfHEZFaNJpz-lcnb3w0okrbM',
        q: '3I1qeEDslZFB8iNfpKAdWtz_Wzm6-jayT_V6aIvhvMj5mnU-Xpj75zLPQSGa9wunMlOoZW9w1wDO1FVuDhwzeOJaTm-Ds0MezeC4U6nVGyyDHb4CUA3ml2tzt4yLrqGYMT7XbADSvuWYADHw79OFjEi4T3s3tJymhaBvy1ulv8M',
        qi: 'wSbXte9PcPtr788e713KHQ4waE26CzoXx-JNOgN0iqJMN6C4_XJEX-cSvCZDf4rh7xpXN6SGLVd5ibIyDJi7bbi5EQ5AXjazPbLBjRthcGXsIuZ3AtQyR0CEWNSdM7EyM5TRdyZQ9kftfz9nI03guW3iKKASETqX2vh0Z8XRjyU',
      }).then(registerKey.bind(this));
      /* eslint-enable */
    }

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
