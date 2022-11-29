import merge from 'lodash/merge.js';

import { Check, Prompt, base } from '../../lib/helpers/interaction_policy/index.js';
import getConfig from '../default.config.js';

const config = getConfig();

config.extraParams = ['triggerCustomFail', 'triggerUnrequestable'];
merge(config.features, {
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

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  },
};
