const { cloneDeep } = require('lodash');

const config = cloneDeep(require('../../default.config'));
const { Prompt, Check, DEFAULT } = require('../../../lib/helpers/interaction_policy');

config.extraParams = ['triggerCustomFail'];
config.features = { requestUri: { enabled: false } };

config.interactions = { policy: cloneDeep(DEFAULT) };

const check = new Check(
  'reason_foo',
  'error_description_foo',
  'error_foo',
  (ctx) => {
    if (ctx.oidc.params.triggerCustomFail) {
      return true;
    }
    return false;
  },
);

config.interactions.policy[0].checks.push(check);
config.interactions.policy.push(new Prompt({ name: 'unrequestable', requestable: false }));

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-no-refresh',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    application_type: 'native',
    client_id: 'client-native',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code', 'none'],
    redirect_uris: ['com.example.app:/cb'],
  }, {
    client_id: 'client-limited-scope',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
    scope: 'openid',
  }],
};
