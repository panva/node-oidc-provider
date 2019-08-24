const difference = require('lodash/difference');
const isEmpty = require('lodash/isEmpty');
const get = require('lodash/get');
const Debug = require('debug');

const debug = new Debug('oidc-provider:userinfo');
const uidToGrantId = new Debug('oidc-provider:uid');

const { InvalidToken, InvalidScope } = require('../helpers/errors');
const setWWWAuthenticate = require('../helpers/set_www_authenticate');
const bodyParser = require('../shared/conditional_body');
const rejectDupes = require('../shared/reject_dupes');
const paramsMiddleware = require('../shared/assemble_params');
const noCache = require('../shared/no_cache');
const { 'x5t#S256': thumbprint } = require('../helpers/calculate_thumbprint');
const instance = require('../helpers/weak_cache');

const PARAM_LIST = new Set([
  'scope',
  'access_token',
]);

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');

module.exports = [
  noCache,

  function setFapiInteractionId(ctx, next) {
    if (instance(ctx.oidc.provider).configuration('features.fapiRW.enabled')) {
      const header = ctx.get('x-fapi-interaction-id');
      if (header) {
        ctx.set('x-fapi-interaction-id', header);
      }
    }

    return next();
  },

  async function setWWWAuthenticateHeader(ctx, next) {
    try {
      await next();
    } catch (err) {
      if (err.expose) {
        let scheme;

        if (/dpop/i.test(err.error_description) || (ctx.oidc.accessToken && ctx.oidc.accessToken['jkt#S256'])) {
          scheme = 'DPoP';
        } else {
          scheme = 'Bearer';
        }

        setWWWAuthenticate(ctx, scheme, {
          realm: ctx.oidc.issuer,
          ...(err.error_description !== 'no access token provided' ? {
            error: err.message,
            error_description: err.error_description,
            scope: err.scope,
          } : undefined),
        });
      }
      throw err;
    }
  },

  parseBody,
  paramsMiddleware.bind(undefined, PARAM_LIST),
  rejectDupes.bind(undefined, {}),

  async function validateAccessToken(ctx, next) {
    const accessToken = await ctx.oidc.provider.AccessToken.find(ctx.oidc.getAccessToken({
      acceptDPoP: true,
      acceptQueryParam: !instance(ctx.oidc.provider).configuration('features.fapiRW.enabled'),
    }));

    ctx.assert(accessToken, new InvalidToken('access token not found'));

    ctx.oidc.entity('AccessToken', accessToken);

    if (accessToken.grantId) {
      uidToGrantId('switched from uid=%s to value of grantId=%s', ctx.oidc.uid, accessToken.grantId);
      ctx.oidc.uid = accessToken.grantId;
    }

    if (!accessToken.scope || !accessToken.scope.split(' ').includes('openid')) {
      throw new InvalidToken('access token missing openid scope');
    }

    if (accessToken['x5t#S256']) {
      const getCertificate = instance(ctx.oidc.provider).configuration('features.mTLS.getCertificate');
      const cert = getCertificate(ctx);
      if (!cert || accessToken['x5t#S256'] !== thumbprint(cert)) {
        throw new InvalidToken('failed x5t#S256 verification');
      }
    }

    const { dPoP } = ctx.oidc;

    if (dPoP) {
      const unique = await ctx.oidc.provider.ReplayDetection.unique(
        accessToken.clientId, dPoP.jti, dPoP.iat + instance(ctx.oidc.provider).configuration('features.dPoP.iatTolerance'),
      );

      ctx.assert(unique, new InvalidToken('DPoP Token Replay detected'));
    }

    if (accessToken['jkt#S256'] && (!dPoP || accessToken['jkt#S256'] !== dPoP.jwk.thumbprint)) {
      throw new InvalidToken('failed jkt#S256 verification');
    }

    await next();
  },

  async function validateScope(ctx, next) {
    if (ctx.oidc.params.scope) {
      const accessTokenScopes = ctx.oidc.accessToken.scope.split(' ');
      const missing = difference(ctx.oidc.params.scope.split(' '), accessTokenScopes);

      if (!isEmpty(missing)) {
        throw new InvalidScope('access token missing requested scope', missing.join(' '));
      }
    }
    await next();
  },

  async function loadClient(ctx, next) {
    const client = await ctx.oidc.provider.Client.find(ctx.oidc.accessToken.clientId);
    ctx.assert(client, new InvalidToken('associated client not found'));

    ctx.oidc.entity('Client', client);

    await next();
  },

  async function loadAccount(ctx, next) {
    const account = await ctx.oidc.provider.Account.findAccount(
      ctx,
      ctx.oidc.accessToken.accountId,
      ctx.oidc.accessToken,
    );

    ctx.assert(account, new InvalidToken('associated account not found'));
    ctx.oidc.entity('Account', account);

    await next();
  },

  async function respond(ctx, next) {
    const claims = get(ctx.oidc.accessToken, 'claims.userinfo', {});
    const rejected = get(ctx.oidc.accessToken, 'claims.rejected', []);
    const scope = ctx.oidc.params.scope || ctx.oidc.accessToken.scope;
    const { client } = ctx.oidc;

    if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
      const token = new ctx.oidc.provider.IdToken(
        await ctx.oidc.account.claims('userinfo', scope, claims, rejected),
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
        await ctx.oidc.account.claims('userinfo', scope, claims, rejected),
        { ctx },
      );

      mask.scope(scope);
      mask.mask(claims);
      mask.rejected(rejected);

      ctx.body = await mask.result();
    }

    debug('uid=%s content-type=%s response=%o', ctx.oidc.uid, ctx.type, ctx.body);
    await next();
  },
];
