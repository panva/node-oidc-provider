'use strict';

const _ = require('lodash');
const bufferEqualsConstant = require('buffer-equals-constant');
const compose = require('koa-compose');
const crypto = require('crypto');
const uuid = require('node-uuid');

const bodyMiddleware = require('../middlewares/selective_body');
const getBearer = require('../middlewares/get_bearer');

const errors = require('../helpers/errors');
const body = bodyMiddleware('application/json');

module.exports = function registrationAction(provider) {
  return {
    post: compose([
      body,
      function * registrationResponse() {
        const params = {};

        Object.assign(params, this.request.body, {
          client_id: uuid.v4(),
          client_secret: crypto.randomBytes(48).toString('base64'),
          client_secret_expires_at: 0,
          registration_access_token: crypto.randomBytes(48).toString('base64'),
        });

        const client = yield provider.addClient(params);

        const response = Object.assign({
          registration_client_uri: this.oidc.urlFor('registration_client', {
            clientId: params.client_id,
          }),
        }, _.mapKeys(client, (value, key) => _.snakeCase(key)));

        this.body = response;

        this.status = 201;
      },
    ]),

    get: compose([

      getBearer,

      function * validateAccessToken(next) {
        const client = provider.Client.find(this.params.clientId);

        this.assert(client,
          new errors.InvalidClientError());

        const valid = bufferEqualsConstant(
          new Buffer(client.registrationAccessToken || '', 'utf8'),
          new Buffer(this.oidc.bearer, 'utf8'),
          1024
        );

        this.assert(valid, new errors.InvalidTokenError());

        this.oidc.client = client;

        yield next;
      },

      function * clientResponse() {
        this.body = _.mapKeys(this.oidc.client, (value, key) => _.snakeCase(key));

        this.body.registration_client_uri =
          this.oidc.urlFor('registration_client', {
            clientId: this.params.clientId,
          });
      },
    ]),
  };
};
