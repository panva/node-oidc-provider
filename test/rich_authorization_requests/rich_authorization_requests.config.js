import getConfig from '../default.config.js';
import {
  InvalidAuthorizationDetails,
  InvalidTarget,
} from '../../lib/helpers/errors.js';

const API = 'https://api.example.com';
const JWT_API = 'https://jwt.example.com';
const PAYMENT_FIELDS = new Set([
  'type',
  'locations',
  'actions',
  'datatypes',
  'identifier',
  'privileges',
  'currency',
  'amount',
]);

export const rarState = {
  accessTokenCalls: [],
  clearAccessTokenResult: false,
  emptyAccessTokenResult: false,
  emptyIntrospectionResult: false,
  filterIntrospectionByAudience: false,
  grantSourceCalls: [],
  introspectionCalls: [],
  validationCalls: [],
  invalidAccessTokenResult: false,
  invalidIntrospectionResult: false,
};

export function resetRarState() {
  rarState.accessTokenCalls.length = 0;
  rarState.clearAccessTokenResult = false;
  rarState.emptyAccessTokenResult = false;
  rarState.emptyIntrospectionResult = false;
  rarState.filterIntrospectionByAudience = false;
  rarState.grantSourceCalls.length = 0;
  rarState.introspectionCalls.length = 0;
  rarState.validationCalls.length = 0;
  rarState.invalidAccessTokenResult = false;
  rarState.invalidIntrospectionResult = false;
}

function requestedAuthorizationDetails(ctx, source) {
  if (ctx.oidc.params.authorization_details !== undefined) {
    return JSON.parse(ctx.oidc.params.authorization_details);
  }

  return source?.rar;
}

const config = getConfig();

config.scopes = ['openid', 'api:read'];
config.issueRefreshToken = (_ctx, client) => client.grantTypeAllowed('refresh_token');
config.features.clientCredentials = { enabled: true };
config.features.deviceFlow = { enabled: true };
config.features.introspection = { enabled: true };
config.features.pushedAuthorizationRequests = { enabled: true };
config.features.requestObjects = { enabled: true };
config.features.ciba = {
  enabled: true,
  processLoginHint(_ctx, loginHint) {
    return loginHint;
  },
  processLoginHintToken(_ctx, loginHintToken) {
    return loginHintToken;
  },
  triggerAuthenticationDevice() {},
  validateBindingMessage() {},
  validateRequestContext() {},
  verifyUserCode() {},
};
config.features.resourceIndicators = {
  enabled: true,
  defaultResource() {
    return undefined;
  },
  getResourceServerInfo(_ctx, resource) {
    if (resource !== API && resource !== JWT_API) {
      throw new InvalidTarget();
    }

    return {
      audience: resource,
      accessTokenFormat: resource === JWT_API ? 'jwt' : 'opaque',
      scope: 'api:read',
    };
  },
  useGrantedResource() {
    return true;
  },
};
config.features.richAuthorizationRequests = {
  enabled: true,
  types: {
    account_information: {
      async validate() {},
    },
    payment: {
      async validate(_ctx, detail) {
        await new Promise((resolve) => { setImmediate(resolve); });
        rarState.validationCalls.push(detail);

        const unknown = Object.keys(detail).find((field) => !PAYMENT_FIELDS.has(field));
        if (unknown) {
          throw new InvalidAuthorizationDetails(`unexpected payment authorization detail field '${unknown}'`);
        }

        if ('currency' in detail && !/^[A-Z]{3}$/.test(detail.currency)) {
          throw new InvalidAuthorizationDetails("'currency' must be a three-letter uppercase code");
        }

        if ('amount' in detail && (typeof detail.amount !== 'number' || detail.amount <= 0)) {
          throw new InvalidAuthorizationDetails("'amount' must be a positive number");
        }
      },
    },
  },
  authorizationDetailsForGrantSource(ctx, source) {
    rarState.grantSourceCalls.push(source);
    return ctx.oidc.grant?.rar ?? requestedAuthorizationDetails(ctx);
  },
  authorizationDetailsForAccessToken(ctx, token, source, grantType) {
    rarState.accessTokenCalls.push({
      grantType,
      source,
      token,
      resource: token.resourceServer?.identifier(),
    });

    if (rarState.invalidAccessTokenResult) {
      return [null];
    }

    if (rarState.clearAccessTokenResult) {
      return undefined;
    }

    if (rarState.emptyAccessTokenResult) {
      return [];
    }

    return requestedAuthorizationDetails(ctx, source);
  },
  authorizationDetailsForIntrospection(ctx, token) {
    rarState.introspectionCalls.push({
      client: ctx.oidc.client,
      token,
    });

    if (rarState.invalidIntrospectionResult) {
      return [null];
    }

    if (rarState.emptyIntrospectionResult) {
      return [];
    }

    if (rarState.filterIntrospectionByAudience) {
      return token.rar.filter((detail) => detail.locations?.includes(token.aud));
    }

    return token.rar;
  },
};

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: [
      'authorization_code',
      'implicit',
      'client_credentials',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code',
      'urn:openid:params:grant-type:ciba',
    ],
    response_types: ['code', 'code token', 'id_token token', 'id_token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
    scope: 'openid api:read',
    authorization_details_types: ['payment'],
    backchannel_token_delivery_mode: 'poll',
    request_object_signing_alg: 'HS256',
  },
};
