import { strict as assert } from 'node:assert';
import * as events from 'node:events';

import getConfig from '../default.config.js';

const config = getConfig();

export const emitter = new events.EventEmitter();

config.extraParams = {
  extra: null,
  extra2(ctx) {
    if (ctx.oidc.params.login_hint) {
      ctx.oidc.params.extra2 ||= 'defaulted';
    }
  },
};
config.features.encryption = {
  enabled: true,
};
config.features.ciba = {
  enabled: true,
  deliveryModes: ['poll', 'ping'],
  processLoginHint(ctx, loginHint) {
    assert(ctx?.oidc);
    assert(typeof loginHint === 'string');
    emitter.emit('processLoginHint', ctx, loginHint);
    return loginHint;
  },
  processLoginHintToken(ctx, loginHintToken) {
    assert(ctx?.oidc);
    assert(typeof loginHintToken === 'string');
    emitter.emit('processLoginHintToken', ctx, loginHintToken);
    if (loginHintToken === 'notfound') {
      return undefined;
    }
    return loginHintToken;
  },
  validateBindingMessage(ctx, bindingMessage) {
    assert(ctx?.oidc);
    assert(bindingMessage === undefined || typeof bindingMessage === 'string');
    emitter.emit('validateBindingMessage', ctx, bindingMessage);
  },
  validateRequestContext(ctx, requestContext) {
    assert(ctx?.oidc);
    assert(requestContext === undefined || typeof requestContext === 'string');
    emitter.emit('validateRequestContext', ctx, requestContext);
  },
  verifyUserCode(ctx, account, userCode) {
    assert(ctx?.oidc);
    assert(account?.accountId && typeof account.claims === 'function');
    assert(userCode === undefined || typeof userCode === 'string');
    emitter.emit('verifyUserCode', ctx, account, userCode);
  },
  triggerAuthenticationDevice(...args) {
    emitter.emit('triggerAuthenticationDevice', ...args);
  },
};

export default {
  config,
  clients: [
    {
      client_id: 'client',
      grant_types: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      backchannel_token_delivery_mode: 'poll',
    },
    {
      client_id: 'client-ping',
      grant_types: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      backchannel_client_notification_endpoint: 'https://rp.example.com/ping',
      backchannel_token_delivery_mode: 'ping',
    },
    {
      client_id: 'client-user-code',
      grant_types: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      backchannel_token_delivery_mode: 'poll',
      backchannel_user_code_parameter: true,
    },
    {
      client_id: 'client-par-required',
      grant_types: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      backchannel_token_delivery_mode: 'poll',
      require_pushed_authorization_requests: true,
    },
    {
      client_id: 'client-signed',
      grant_types: ['urn:openid:params:grant-type:ciba', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      backchannel_token_delivery_mode: 'poll',
      backchannel_authentication_request_signing_alg: 'ES256',
      jwks_uri: 'https://rp.example.com/jwks',
    },
    {
      client_id: 'client-not-allowed',
      token_endpoint_auth_method: 'none',
      grant_types: [],
      redirect_uris: [],
      response_types: [],
    },
  ],
};
