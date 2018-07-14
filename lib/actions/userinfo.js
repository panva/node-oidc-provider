const _ = require('lodash');
const Debug = require('debug');

const debug = new Debug('oidc-provider:userinfo');
const uuidToGrantId = new Debug('oidc-provider:uuid');

const { InvalidToken, InvalidScope } = require('../helpers/errors');
const getMask = require('../helpers/claims');
const instance = require('../helpers/weak_cache');
const setWWWAuthenticate = require('../helpers/set_www_authenticate');
const bodyParser = require('../shared/conditional_body');
const rejectDupes = require('../shared/reject_dupes');
const params = require('../shared/assemble_params');
const noCache = require('../shared/no_cache');

const PARAM_LIST = [
  'scope',
  'access_token',
];

const parseBody = bodyParser('application/x-www-form-urlencoded');
const getParams = params(PARAM_LIST);

module.exports = function userinfoAction(provider) {
  const {
    pairwiseSalt,
    claims: claimsConfig,
    claimsSupported,
    audiences,
  } = instance(provider).configuration();

  const Claims = getMask({ pairwiseSalt, claimsSupported, claims: claimsConfig });

  return [
    noCache,

    async function setWWWAuthenticateHeader(ctx, next) {
      try {
        await next();
      } catch (err) {
        if (err.expose) {
          setWWWAuthenticate(ctx, 'Bearer', {
            realm: provider.issuer,
            ...(err.error_description !== 'no bearer auth mechanism provided' ? {
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
    getParams,
    rejectDupes,

    async function validateBearer(ctx, next) {
      const accessToken = await provider.AccessToken.find(ctx.oidc.bearer);
      ctx.assert(accessToken, new InvalidToken());

      uuidToGrantId('switched from uuid=%s to value of grantId=%s', ctx.oidc.uuid, accessToken.grantId);
      ctx.oidc.uuid = accessToken.grantId;

      ctx.oidc.accessToken = accessToken;
      ctx.oidc.entity('AccessToken', accessToken);
      await next();
    },

    async function validateScope(ctx, next) {
      if (ctx.oidc.params.scope) {
        const accessTokenScopes = ctx.oidc.accessToken.scope.split(' ');
        const missing = _.difference(
          ctx.oidc.params.scope.split(' '),
          accessTokenScopes, // TODO: ignore unrecognized scopes?
        );

        if (!_.isEmpty(missing)) {
          throw new InvalidScope('access token missing requested scope', missing.join(' '));
        }
      }
      await next();
    },

    async function loadClient(ctx, next) {
      const client = await provider.Client.find(ctx.oidc.accessToken.clientId);
      ctx.assert(client, new InvalidToken());

      ctx.oidc.entity('Client', client);

      await next();
    },

    async function loadAccount(ctx, next) {
      const account = await provider.Account.findById(
        ctx,
        ctx.oidc.accessToken.accountId,
        ctx.oidc.accessToken,
      );

      ctx.assert(account, new InvalidToken());
      ctx.oidc.entity('Account', account);

      await next();
    },

    async function respond(ctx, next) {
      const claims = _.get(ctx.oidc.accessToken, 'claims.userinfo', {});
      const scope = ctx.oidc.params.scope || ctx.oidc.accessToken.scope;
      const { client } = ctx.oidc;

      if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
        const { IdToken } = provider;
        const token = new IdToken(
          await ctx.oidc.account.claims('userinfo', scope),
          client.sectorIdentifier,
        );

        token.scope = scope;
        token.mask = claims;

        ctx.body = await token.sign(client, {
          audiences: await audiences(
            ctx,
            ctx.oidc.accessToken.accountId,
            ctx.oidc.accessToken,
            'userinfo',
            scope,
          ),
          expiresAt: ctx.oidc.accessToken.exp,
          use: 'userinfo',
        });
        ctx.type = 'application/jwt; charset=utf-8';
      } else {
        const mask = new Claims(
          await ctx.oidc.account.claims('userinfo', scope),
          client.sectorIdentifier,
        );

        mask.scope(scope);
        mask.mask(claims);

        ctx.body = mask.result();
      }

      debug('uuid=%s content-type=%s response=%o', ctx.oidc.uuid, ctx.type, ctx.body);
      await next();
    },
  ];
};
