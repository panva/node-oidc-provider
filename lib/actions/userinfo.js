'use strict';

const _ = require('lodash');
const compose = require('koa-compose');

const errors = require('../helpers/errors');
const getMask = require('../helpers/claims');
const instance = require('../helpers/weak_cache');

const bodyParser = require('../shared/conditional_body');
const rejectDupes = require('../shared/check_dupes');
const params = require('../shared/get_params');
const errorHandler = require('../shared/error_handler');

const PARAM_LIST = [
  'scope',
  'access_token',
];

const parseBody = bodyParser('application/x-www-form-urlencoded');
const getParams = params(PARAM_LIST);

module.exports = function userinfoAction(provider) {
  const Claims = getMask(instance(provider).configuration());

  return compose([
    async function setAuthenticate(ctx, next) {
      await next();
      if (ctx.status === 401) {
        const wwwAuth = _.chain({
          realm: provider.issuer,
        })
          .merge(ctx.body)
          .map((val, key) => `${key}="${val}"`)
          .value()
          .join(', ');

        ctx.set('WWW-Authenticate', `Bearer ${wwwAuth}`);
      }
    },

    errorHandler(provider, 'userinfo.error'),

    parseBody,

    getParams,

    rejectDupes,

    async function validateBearer(ctx, next) {
      const accessToken = await provider.AccessToken.find(ctx.oidc.bearer);
      ctx.assert(accessToken, new errors.InvalidTokenError());

      ctx.oidc.accessToken = accessToken;
      await next();
    },

    async function validateScope(ctx, next) {
      if (ctx.oidc.params.scope) {
        const accessTokenScopes = ctx.oidc.accessToken.scope.split(' ');
        const missing = _.difference(ctx.oidc.params.scope.split(' '),
          accessTokenScopes);

        ctx.assert(_.isEmpty(missing), 400, 'invalid_scope', {
          error_description: 'access token missing requested scope',
          scope: missing.join(' '),
        });
      }
      await next();
    },

    async function loadClient(ctx, next) {
      const client = await provider.Client.find(ctx.oidc.accessToken.clientId);
      ctx.assert(client, new errors.InvalidTokenError());

      ctx.oidc.client = client;

      await next();
    },

    async function loadAccount(ctx, next) {
      const account = await provider.Account.findById.call(ctx, ctx.oidc.accessToken.accountId);

      ctx.assert(account, new errors.InvalidTokenError());

      ctx.oidc.account = account;

      await next();
    },

    async function respond(ctx, next) {
      const claims = _.get(ctx.oidc.accessToken, 'claims.userinfo', {});
      const scope = ctx.oidc.params.scope || ctx.oidc.accessToken.scope;
      const client = ctx.oidc.client;

      if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
        const IdToken = provider.IdToken;
        const token = new IdToken(await Promise.resolve(ctx.oidc.account.claims()),
          client.sectorIdentifier);

        token.scope = scope;
        token.mask = claims;

        ctx.body = await token.sign(client, {
          expiresAt: ctx.oidc.accessToken.exp,
          use: 'userinfo',
        });
        ctx.type = 'application/jwt; charset=utf-8';
      } else {
        const mask = new Claims(await Promise.resolve(ctx.oidc.account.claims()),
          client.sectorIdentifier);

        mask.scope(scope);
        mask.mask(claims);

        ctx.body = mask.result();
      }

      await next();
    },
  ]);
};
