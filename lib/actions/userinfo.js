import difference from '../helpers/_/difference.js';
import bodyParser from '../shared/conditional_body.js';
import rejectDupes from '../shared/reject_dupes.js';
import paramsMiddleware from '../shared/assemble_params.js';
import noCache from '../shared/no_cache.js';
import filterClaims from '../helpers/filter_claims.js';
import isValidScope from '../helpers/is_valid_scope.js';
import { InvalidRequest, InvalidToken, InsufficientScope } from '../helpers/errors.js';
import getCtxAccountClaims from '../helpers/account_claims.js';
import getSetWWWAuthenticateHeader from '../shared/set_www_authenticate_header.js';
import {
  getValidateAccessToken,
  loadAccessTokenAccount,
  loadAccessTokenClient,
  loadAccessTokenGrant,
} from '../shared/access_token.js';

const PARAM_LIST = new Set([
  'scope',
  'access_token',
]);

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');

const validateAccessToken = getValidateAccessToken({
  afterFind(_ctx, accessToken) {
    if (!accessToken.scopes.size || !accessToken.scopes.has('openid')) {
      throw new InsufficientScope('access token missing openid scope', 'openid');
    }
  },
});

export default [
  noCache,

  getSetWWWAuthenticateHeader(),

  parseBody,
  paramsMiddleware.bind(undefined, PARAM_LIST),
  rejectDupes.bind(undefined, {}),

  validateAccessToken,

  function validateAudience(ctx, next) {
    const { oidc: { entities: { AccessToken: accessToken } } } = ctx;

    if (accessToken.aud !== undefined) {
      throw new InvalidToken('token audience prevents accessing the userinfo endpoint');
    }

    return next();
  },

  async function validateScope(ctx, next) {
    if (ctx.oidc.params.scope) {
      if (!isValidScope(ctx.oidc.params.scope)) {
        throw new InvalidRequest('scope contains invalid characters');
      }

      const missing = difference(ctx.oidc.params.scope.split(' '), [...ctx.oidc.accessToken.scopes]);

      if (missing.length !== 0) {
        throw new InsufficientScope('access token missing requested scope', missing.join(' '));
      }
    }
    await next();
  },

  loadAccessTokenClient,
  loadAccessTokenAccount,
  loadAccessTokenGrant,

  async function respond(ctx) {
    const claims = filterClaims(ctx.oidc.accessToken.claims, 'userinfo', ctx.oidc.grant);
    const rejected = ctx.oidc.grant.getRejectedOIDCClaims();
    const scope = ctx.oidc.grant.getOIDCScopeFiltered(new Set((ctx.oidc.params.scope || ctx.oidc.accessToken.scope).split(' ')));
    const { client } = ctx.oidc;

    if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
      const token = new ctx.oidc.provider.IdToken(
        await getCtxAccountClaims(ctx, 'userinfo', scope, claims, rejected),
        { ctx },
      );

      token.scope = scope;
      token.mask = claims;
      token.rejected = rejected;

      ctx.body = await token.issue({
        expiresAt: ctx.oidc.accessToken.exp,
        use: 'userinfo',
      });
      ctx.type = 'application/jwt; charset=utf-8';
    } else {
      const mask = new ctx.oidc.provider.Claims(
        await getCtxAccountClaims(ctx, 'userinfo', scope, claims, rejected),
        { ctx },
      );

      mask.scope(scope);
      mask.mask(claims);
      mask.rejected(rejected);

      ctx.body = await mask.result();
    }
  },
];
