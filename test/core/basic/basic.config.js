const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../../default.config'));
const { Prompt, Check, base } = require('../../../lib/helpers/interaction_policy');

config.extraParams = ['triggerCustomFail'];
merge(config.features, { requestObjects: { requestUri: false } });
config.responseTypes = ['id_token', 'code', 'none'];

const policy = base();

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

policy.get('login').checks.add(check);
policy.add(new Prompt({ name: 'unrequestable', requestable: false }));

config.interactions = { policy };

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
