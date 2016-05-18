'use strict';

const _ = require('lodash');
const compose = require('koa-compose');

const errors = require('../helpers/errors');
const getMask = require('../helpers/claims');

const body = require('../middlewares/selective_body');
const dupes = require('../middlewares/check_dupes');
const getBearer = require('../middlewares/get_bearer');
const params = require('../middlewares/get_params');
const errorHandler = require('../middlewares/api_error_handler');

const PARAM_LIST = [
  'scope',
  'access_token',
];

const bodyMiddleware = body('application/x-www-form-urlencoded');
const getParams = params({ whitelist: PARAM_LIST });

module.exports = function userinfoAction(provider) {
  const Claims = getMask(provider.configuration);

  return compose([
    function * setAuthenticate(next) {
      yield next;
      if (this.status === 401) {
        const wwwAuth = _.chain({
          realm: provider.issuer,
        })
          .merge(this.body)
          .map((val, key) => `${key}="${val}"`)
          .value()
          .join(', ');

        this.set('WWW-Authenticate', `Bearer ${wwwAuth}`);
      }
    },

    errorHandler(provider, 'userinfo.error'),

    function * parseBody(next) {
      if (this.method === 'POST') {
        yield bodyMiddleware.call(this, next);
      } else {
        yield next;
      }
    },

    getParams,

    dupes,

    getBearer,

    function * validateBearer(next) {
      const accessToken = yield provider.AccessToken.find(this.oidc.bearer);
      this.assert(accessToken,
        new errors.InvalidTokenError());

      this.oidc.accessToken = accessToken;
      yield next;
    },

    // TODO: validate requested scopes to be part of the granted token

    function * loadClient(next) {
      const client = provider.Client.find(this.oidc.accessToken.clientId);

      this.assert(client,
        new errors.InvalidTokenError());

      this.oidc.client = client;

      yield next;
    },

    function * loadAccount(next) {
      const account = yield provider.Account.findById(this.oidc.accessToken.accountId);

      this.assert(account, new errors.InvalidTokenError());

      this.oidc.account = account;

      yield next;
    },

    function * respond() {
      const claims = _.get(this.oidc.accessToken, 'claims.userinfo', {});
      const scope = this.oidc.accessToken.scope;
      const client = this.oidc.client;

      if (client.userinfoSignedResponseAlg !== 'none' || client.userinfoEncryptedResponseAlg) {
        const token = new provider.IdToken(this.oidc.account.claims(), client.sectorIdentifier);

        token.scope = scope;
        token.mask = claims;

        this.body = yield token.toJWT(client, {
          expiresAt: this.oidc.accessToken.exp,
          use: 'userinfo',
        });
        this.type = 'application/jwt; charset=utf-8';
      } else {
        const mask = new Claims(this.oidc.account.claims(), client.sectorIdentifier);

        mask.scope(scope);
        mask.mask(claims);

        this.body = mask.result();
      }
    },
  ]);
};
