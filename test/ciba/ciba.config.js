const { strict: assert } = require('assert');

const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.features.encryption = {
  enabled: true,
};
config.features.ciba = {
  enabled: true,
  deliveryModes: ['poll', 'ping'],
  processLoginHint(ctx, loginHint) {
    assert(ctx && ctx.oidc);
    assert(typeof loginHint === 'string');
    return loginHint;
  },
  processLoginHintToken(ctx, loginHintToken) {
    assert(ctx && ctx.oidc);
    assert(typeof loginHintToken === 'string');
    return loginHintToken;
  },
  validateBindingMessage(ctx, bindingMessage) {
    assert(ctx && ctx.oidc);
    assert(bindingMessage === undefined || typeof bindingMessage === 'string');
  },
  validateRequestContext(ctx, requestContext) {
    assert(ctx && ctx.oidc);
    assert(requestContext === undefined || typeof requestContext === 'string');
  },
  verifyUserCode(ctx, account, userCode) {
    assert(ctx && ctx.oidc);
    assert(account && account.accountId && typeof account.claims === 'function');
    assert(userCode === undefined || typeof userCode === 'string');
  },
};

module.exports = {
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
      backchannel_authentication_request_signing_alg: 'RS256',
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
