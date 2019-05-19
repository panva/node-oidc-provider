const { cloneDeep } = require('lodash');

const config = cloneDeep(require('../default.config'));
const { Check, Prompt, DEFAULT } = require('../../lib/helpers/interaction');

config.extraParams = ['triggerCustomFail', 'triggerUnrequestable'];
config.features = { sessionManagement: { enabled: true } };

config.interactions = cloneDeep(DEFAULT);

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

config.interactions[0].checks.push(check);
config.interactions.push(new Prompt({ name: 'custom', requestable: true }));
config.interactions.unshift(new Prompt({ name: 'unrequestable', requestable: false }, new Check('un_foo', 'un_foo_desc', 'un_foo_err', (ctx) => {
  if (ctx.oidc.params.triggerUnrequestable && (!ctx.oidc.result || !('foo' in ctx.oidc.result))) {
    return true;
  }
  return false;
})));

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  },
};
