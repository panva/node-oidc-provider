'use strict';

let _ = require('lodash');
let bufferEqualsConstant = require('buffer-equals-constant');
let compose = require('koa-compose');
let crypto = require('crypto');
let uuid = require('node-uuid');

let bodyMiddleware = require('../middlewares/selective_body');
let getBearer = require('../middlewares/get_bearer');

let errors = require('../helpers/errors');
let body = bodyMiddleware({
  only: 'application/json',
  raise: true,
});

module.exports = function(provider) {

  return {
    post: compose([

      body,

      function * () {

        let params = {};

        Object.assign(params, this.request.body, {
          client_id: uuid.v4(),
          client_secret: crypto.randomBytes(48).toString('base64'),
          client_secret_expires_at: 0,
          registration_access_token: crypto.randomBytes(48).toString('base64'),
        });

        let client = yield provider.Client.add(params);

        let response = Object.assign({
          registration_client_uri: this.oidc.urlFor('registration_client', {
            clientId: params.client_id,
          }),
        }, _.mapKeys(client, (value, key) => {
          return _.snakeCase(key);
        }));

        this.body = response;

        this.status = 201;
      },
    ]),

    get: compose([

      getBearer,

      function * (next) {
        let client = provider.Client.find(this.params.clientId);

        this.assert(client,
          new errors.InvalidClientError());

        let valid = bufferEqualsConstant(
          new Buffer('' + client.registrationAccessToken, 'utf8'),
          new Buffer('' + this.oidc.bearer, 'utf8'),
          1024
        );

        this.assert(valid, new errors.InvalidTokenError());

        this.oidc.client = client;

        yield next;
      },

      function * () {
        this.body = _.mapKeys(this.oidc.client, (value, key) => {
          return _.snakeCase(key);
        });

        this.body.registration_client_uri =
          this.oidc.urlFor('registration_client', {
            clientId: this.params.clientId,
          });
      },
    ]),
  };
};
