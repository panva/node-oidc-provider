'use strict';

let _ = require('lodash');
let compose = require('koa-compose');

let errors = require('../helpers/errors');

let body = require('../middlewares/selective_body');
let dupes = require('../middlewares/check_dupes');
let getBearer = require('../middlewares/get_bearer');
let params = require('../middlewares/get_params');
let errorHandler = require('../middlewares/api_error_handler');

const PARAM_LIST = [
  'scope',
  'access_token',
];

let bodyMiddleware = body({
  only: 'application/x-www-form-urlencoded',
  raise: true,
});

let getParams = params({
  whitelist: PARAM_LIST,
});

module.exports = function (provider) {

  let ClaimsMask = require('../helpers/claims_mask')(provider.configuration);

  return compose([

    function * setAuthenticate(next) {
      yield next;
      if (this.status === 401) {
        let wwwAuth = _.chain({
          realm: provider.issuer,
        }).merge(this.body).map(function (val, key) {
          return `${key}="${val}"`;
        }).value().join(', ');

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
      let accessToken = yield provider.AccessToken.find(this.oidc.bearer);
      this.assert(accessToken,
        new errors.InvalidTokenError());

      this.oidc.accessToken = accessToken;
      yield next;
    },

    // TODO: validate requested scopes to be part of the granted token

    function * loadClient(next) {
      let client = provider.Client.find(this.oidc.accessToken.clientId);

      this.assert(client,
        new errors.InvalidTokenError());

      this.oidc.client = client;

      yield next;
    },

    function * loadAccount(next) {
      let account = yield provider.Account.findById(
        this.oidc.accessToken.accountId);

      this.assert(account,
        new errors.InvalidTokenError());

      this.oidc.account = account;

      yield next;
    },

    function * respond() {
      let claims = _.get(this.oidc.accessToken, 'claims.userinfo', {});
      let scope = this.oidc.accessToken.scope;
      let client = this.oidc.client;

      if (
        client.userinfoSignedResponseAlg !== 'none' ||
          client.userinfoEncryptedResponseAlg) {

        let token = new provider.IdToken(
          this.oidc.account.claims(), client.sectorIdentifier);

        token.scope = scope;
        token.mask = claims;

        this.body = yield token.toJWT(client, {
          expiresAt: this.oidc.accessToken.exp,
          use: 'userinfo',
        });

        this.type = 'application/jwt; charset=utf-8';

      } else {
        let mask = new ClaimsMask(this.oidc.account.claims(),
          client.sectorIdentifier);
        mask.scope = scope;
        mask.mask = claims;

        this.body = mask.result();
      }
    },
  ]);
};
