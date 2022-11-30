import merge from 'lodash/merge.js';

import { Prompt, Check, base } from '../../../lib/helpers/interaction_policy/index.js';
import getConfig from '../../default.config.js';

const config = getConfig();

config.extraParams = ['triggerCustomFail'];
merge(config.features, {
  pushedAuthorizationRequests: { enabled: false },
  requestObjects: { requestUri: false, request: false },
});
config.responseTypes = ['id_token', 'code', 'none'];
config.allowOmittingSingleRegisteredRedirectUri = false;

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

export default {
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
    grant_types: ['authorization_code', 'refresh_token'],
  }],
};
