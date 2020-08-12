const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));
const { Check, Prompt, base } = require('../../lib/helpers/interaction_policy');

config.extraParams = ['triggerCustomFail', 'triggerUnrequestable'];
merge(config.features, {
  sessionManagement: { enabled: true },
  rpInitiatedLogout: { enabled: false },
});

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
policy.add(new Prompt({ name: 'custom', requestable: true }));
policy.add(new Prompt({ name: 'unrequestable', requestable: false }, new Check('un_foo', 'un_foo_desc', 'un_foo_err', (ctx) => {
  if (ctx.oidc.params.triggerUnrequestable && (!ctx.oidc.result || !('foo' in ctx.oidc.result))) {
    return true;
  }
  return false;
})), 0);

config.interactions = { policy };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  },
};
