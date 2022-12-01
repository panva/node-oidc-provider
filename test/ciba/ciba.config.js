/* eslint-disable prefer-rest-params */

import { strict as assert } from 'node:assert';
import * as events from 'node:events';

import getConfig from '../default.config.js';

const config = getConfig();

export const emitter = new events.EventEmitter();

config.features.encryption = {
  enabled: true,
};
config.features.requestObjects = {
  request: false,
  requestUri: false,
};
config.features.ciba = {
  enabled: true,
  deliveryModes: ['poll', 'ping'],
  processLoginHint(ctx, loginHint) {
    assert(ctx?.oidc);
    assert(typeof loginHint === 'string');
    emitter.emit('processLoginHint', ...arguments);
    return loginHint;
  },
  processLoginHintToken(ctx, loginHintToken) {
    assert(ctx?.oidc);
    assert(typeof loginHintToken === 'string');
    emitter.emit('processLoginHintToken', ...arguments);
    if (loginHintToken === 'notfound') {
      return undefined;
    }
    return loginHintToken;
  },
  validateBindingMessage(ctx, bindingMessage) {
    assert(ctx?.oidc);
    assert(bindingMessage === undefined || typeof bindingMessage === 'string');
    emitter.emit('validateBindingMessage', ...arguments);
  },
  validateRequestContext(ctx, requestContext) {
    assert(ctx?.oidc);
    assert(requestContext === undefined || typeof requestContext === 'string');
    emitter.emit('validateRequestContext', ...arguments);
  },
  verifyUserCode(ctx, account, userCode) {
    assert(ctx?.oidc);
    assert(account?.accountId && typeof account.claims === 'function');
    assert(userCode === undefined || typeof userCode === 'string');
    emitter.emit('verifyUserCode', ...arguments);
  },
  triggerAuthenticationDevice() {
    emitter.emit('triggerAuthenticationDevice', ...arguments);
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
