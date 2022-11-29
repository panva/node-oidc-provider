import presence from '../helpers/validate_presence.js';
import getTokenAuth from '../shared/token_auth.js';
import noCache from '../shared/no_cache.js';
import instance from '../helpers/weak_cache.js';
import { urlencoded as parseBody } from '../shared/selective_body.js';
import rejectDupes from '../shared/reject_dupes.js';
import paramsMiddleware from '../shared/assemble_params.js';
import { InvalidRequest } from '../helpers/errors.js';

const introspectable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);
const JWT = 'application/token-introspection+jwt';

export default function introspectionAction(provider) {
  const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider);
  const PARAM_LIST = new Set(['token', 'token_type_hint', ...authParams]);
  const configuration = instance(provider).configuration();
  const {
    pairwiseIdentifier, features: {
      introspection: { allowedPolicy },
      jwtIntrospection,
    },
  } = configuration;
  const { grantTypeHandlers } = instance(provider);
  const {
    IdToken, AccessToken, ClientCredentials, RefreshToken, Client,
  } = provider;

  function getAccessToken(token) {
    return AccessToken.find(token);
  }

  function getClientCredentials(token) {
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    if (!grantTypeHandlers.has('refresh_token')) {
      return undefined;
    }
    return RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find((found) => !!found);
  }

  return [
    noCache,
    parseBody,
    paramsMiddleware.bind(undefined, PARAM_LIST),
    ...tokenAuth,
    rejectDupes.bind(undefined, {}),

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    async function jwtIntrospectionResponse(ctx, next) {
      if (jwtIntrospection.enabled) {
        const { client } = ctx.oidc;

        const {
          introspectionEncryptedResponseAlg: encrypt,
          introspectionSignedResponseAlg: sign,
        } = client;

        const accepts = ctx.accepts('json', JWT);
        if (encrypt && accepts !== JWT) {
          throw new InvalidRequest(`introspection must be requested with Accept: ${JWT} for this client`);
        }

        await next();

        if ((encrypt || sign) && accepts === JWT) {
          const token = new IdToken({}, { ctx });
          token.extra = {
            token_introspection: ctx.body,
            aud: ctx.body.aud,
          };

          ctx.body = await token.issue({ use: 'introspection' });
          ctx.type = 'application/token-introspection+jwt; charset=utf-8';
        }
      } else {
        await next();
      }
    },

    async function renderTokenResponse(ctx, next) {
      const { params } = ctx.oidc;

      ctx.body = { active: false };

      let token;

      switch (params.token_type_hint) {
        case 'access_token':
          token = await getAccessToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getClientCredentials(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'client_credentials':
          token = await getClientCredentials(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'refresh_token':
          token = await getRefreshToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getClientCredentials(params.token),
              ]).then(findResult);
            });
          break;
        default:
          token = await Promise.all([
            getAccessToken(params.token),
            getClientCredentials(params.token),
            getRefreshToken(params.token),
          ]).then(findResult);
      }

      if (!token || !token.isValid) {
        return;
      }

      if (token.grantId) {
        const grant = await ctx.oidc.provider.Grant.find(token.grantId, {
          ignoreExpiration: true,
        });

        if (!grant) return;
        if (grant.isExpired) return;
        if (grant.clientId !== token.clientId) return;
        if (grant.accountId !== token.accountId) return;

        ctx.oidc.entity('Grant', grant);
      }

      if (introspectable.has(token.kind)) {
        ctx.oidc.entity(token.kind, token);
      } else {
        return;
      }

      if (!(await allowedPolicy(ctx, ctx.oidc.client, token))) {
        return;
      }

      if (token.accountId) {
        ctx.body.sub = token.accountId;
        if (token.clientId !== ctx.oidc.client.clientId) {
          const client = await Client.find(token.clientId);
          if (client.subjectType === 'pairwise') {
            ctx.body.sub = await pairwiseIdentifier(ctx, ctx.body.sub, client);
          }
        } else if (ctx.oidc.client.subjectType === 'pairwise') {
          ctx.body.sub = await pairwiseIdentifier(ctx, ctx.body.sub, ctx.oidc.client);
        }
      }

      Object.assign(ctx.body, {
        ...token.extra,
        active: true,
        client_id: token.clientId,
        exp: token.exp,
        iat: token.iat,
        sid: token.sid,
        iss: provider.issuer,
        jti: token.jti !== params.token ? token.jti : undefined,
        aud: token.aud,
        scope: token.scope,
        cnf: token.isSenderConstrained() ? {} : undefined,
        token_type: token.kind !== 'RefreshToken' ? token.tokenType : undefined,
      });

      if (token['x5t#S256']) {
        ctx.body.cnf['x5t#S256'] = token['x5t#S256'];
      }

      if (token.jkt) {
        ctx.body.cnf.jkt = token.jkt;
      }

      await next();
    },
  ];
}
