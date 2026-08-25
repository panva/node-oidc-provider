import getConfig from '../default.config.js';
import { errors } from '../../lib/index.js';

export const API = 'https://api.example.com';
export const SECOND_API = 'https://api-2.example.com';

const config = getConfig();

config.scopes = ['openid', 'api:read', 'api:write'];
config.enabledJWA.dPoPSigningAlgValues = ['ES256'];
config.extraTokenClaims = (_ctx, token) => token.actor ? { act: token.actor } : {};
config.features.clientCredentials = { enabled: false };
config.features.dPoP = { enabled: true };
config.features.resourceIndicators = {
  enabled: true,
  defaultResource() {
    return undefined;
  },
  getResourceServerInfo(_ctx, resource) {
    if (resource !== API && resource !== SECOND_API) {
      throw new errors.InvalidTarget();
    }

    return {
      audience: resource,
      scope: 'api:read api:write',
    };
  },
  useGrantedResource() {
    return true;
  },
};
config.features.richAuthorizationRequests = {
  enabled: true,
  types: {
    payment: {
      async validate(_ctx, detail) {
        if (typeof detail.amount !== 'number' || detail.amount <= 0) {
          throw new errors.InvalidAuthorizationDetails('payment amount must be positive');
        }
      },
    },
  },
  authorizationDetailsForGrantSource(_ctx, source) {
    return source?.rar;
  },
  authorizationDetailsForAccessToken(ctx, _token, source) {
    if (ctx.oidc.params.authorization_details !== undefined) {
      return JSON.parse(ctx.oidc.params.authorization_details);
    }

    return source?.rar;
  },
  authorizationDetailsForIntrospection(_ctx, token) {
    return token.rar;
  },
};

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
    scope: 'api:read',
    authorization_details_types: ['payment'],
  },
};
