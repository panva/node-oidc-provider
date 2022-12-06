import merge from 'lodash/merge.js';

import * as errors from '../../lib/helpers/errors.js';
import getConfig from '../default.config.js';

const config = getConfig();

merge(config, {
  issueRefreshToken() {
    return true;
  },
  features: {
    introspection: { enabled: true },
    clientCredentials: { enabled: true },
    deviceFlow: { enabled: true },
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

        const resources = Array.isArray(request.resource) ? request.resource : [request.resource];

        for (const resource of resources) {
          grant.addResourceScope(resource, request.scope);
        }

        await grant.save();
        return ctx.oidc.provider.backchannelResult(request, grant.jti);
      },
    },
    resourceIndicators: {
      enabled: true,
      async useGrantedResource(ctx) {
        return ctx.oidc.body?.usegranted;
      },
      getResourceServerInfo(ctx, resource) {
        if (resource.includes('wl')) {
          return {
            audience: resource,
            scope: 'api:read api:write',
          };
        }

        throw new errors.InvalidTarget();
      },
      defaultResource(ctx) {
        if (ctx.oidc.body?.nodefault) {
          return undefined;
        }

        return 'urn:wl:default';
      },
    },
  },
});

export default {
  config,
  clients: [
    {
      client_id: 'client',
      token_endpoint_auth_method: 'none',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: [
        'id_token',
        'id_token token',
        'code',
      ],
      backchannel_token_delivery_mode: 'poll',
      grant_types: [
        'implicit',
        'refresh_token',
        'client_credentials',
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:device_code',
        'urn:openid:params:grant-type:ciba',
      ],
    },
  ],
};
