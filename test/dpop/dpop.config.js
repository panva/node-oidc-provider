import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.enabledJWA.dPoPSigningAlgValues = ['ES256', 'PS256'];
merge(config.features, {
  dPoP: { enabled: true, nonceSecret: Buffer.alloc(32, 0) },
  clientCredentials: { enabled: true },
  introspection: { enabled: true },
  deviceFlow: { enabled: true },
  pushedAuthorizationRequests: { enabled: true },
  requestObjects: { request: true },
  ciba: {
    enabled: true,
    processLoginHint(ctx, loginHint) {
      return loginHint;
    },
    validateBindingMessage() {},
    validateRequestContext() {},
    verifyUserCode() {},
    async triggerAuthenticationDevice(ctx, request) {
      const grant = new ctx.oidc.provider.Grant({
        clientId: request.clientId, accountId: request.accountId,
      });
      grant.addOIDCScope(ctx.oidc.requestParamScopes);
      await grant.save();
      return ctx.oidc.provider.backchannelResult(request, grant.jti);
    },
  },
});

export default {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      grant_types: [
        'authorization_code',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:device_code',
        'urn:openid:params:grant-type:ciba',
        'client_credentials',
      ],
      response_types: ['code'],
      backchannel_token_delivery_mode: 'poll',
      redirect_uris: ['https://client.example.com/cb'],
    },
    {
      client_id: 'client-none',
      grant_types: [
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:device_code',
        'urn:openid:params:grant-type:ciba',
        'refresh_token',
      ],
      response_types: ['code'],
      backchannel_token_delivery_mode: 'poll',
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
    },
  ],
};
