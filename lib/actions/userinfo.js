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
    function* setAuthenticate(next) {
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

    parseBody,

    getParams,

    rejectDupes,

    function* validateBearer(next) {
      const accessToken = yield provider.AccessToken.find(this.oidc.bearer);
      this.assert(accessToken, new errors.InvalidTokenError());

      this.oidc.accessToken = accessToken;
      yield next;
    },

    function* validateScope(next) {
      if (this.oidc.params.scope) {
        const accessTokenScopes = this.oidc.accessToken.scope.split(' ');
        const missing = _.difference(this.oidc.params.scope.split(' '),
          accessTokenScopes);

        this.assert(_.isEmpty(missing), 400, 'invalid_scope', {
          error_description: 'access token missing requested scope',
          scope: missing.join(' '),
        });
      }
      yield next;
    },

    function* loadClient(next) {
      const client = yield provider.Client.find(this.oidc.accessToken.clientId);
      this.assert(client, new errors.InvalidTokenError());

      this.oidc.client = client;

      yield next;
    },

    function* loadAccount(next) {
      const account = yield provider.Account.findById(this.oidc.accessToken.accountId);

      this.assert(account, new errors.InvalidTokenError());

      this.oidc.account = account;

      yield next;
    },

    function* respond() {
      const claims = _.get(this.oidc.accessToken, 'claims.userinfo', {});
      const scope = this.oidc.params.scope || this.oidc.accessToken.scope;
      const client = this.oidc.client;

      if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
        const IdToken = provider.IdToken;
        const token = new IdToken(this.oidc.account.claims(), client.sectorIdentifier);

        token.scope = scope;
        token.mask = claims;

        this.body = yield token.sign(client, {
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
