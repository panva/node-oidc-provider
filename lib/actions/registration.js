'use strict';

const _ = require('lodash');
const compose = require('koa-compose');
const bufferEqualsConstant = require('buffer-equals-constant');
const crypto = require('crypto');
const uuid = require('uuid');

const noCache = require('../shared/no_cache');
const bodyParser = require('../shared/selective_body');

const epochTime = require('../helpers/epoch_time');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const parseBody = bodyParser('application/json');

const FORBIDDEN = [
  'registration_access_token',
  'registration_client_uri',
  'client_secret_expires_at',
  'client_id_issued_at',
];

function findMissingKey(value, key) {
  return FORBIDDEN.indexOf(key) === -1 && !_.has(this.request.body, key) && value !== undefined;
}

module.exports = function registrationAction(provider) {
  const OAuthToken = provider.OAuthToken;

  class RegistrationAccessToken extends OAuthToken {}
  instance(provider).RegistrationAccessToken = RegistrationAccessToken;

  class InitialAccessToken extends OAuthToken {}
  instance(provider).InitialAccessToken = InitialAccessToken;

  function* validateInitialAccessToken(next) {
    const setup = provider.configuration('features.registration');
    switch (setup.initialAccessToken && typeof setup.initialAccessToken) {
      case 'boolean': {
        const initialAccessToken = yield InitialAccessToken.find(this.oidc.bearer);
        this.assert(initialAccessToken, new errors.InvalidTokenError());
        break;
      }
      case 'string': {
        const valid = bufferEqualsConstant(
          new Buffer(setup.initialAccessToken, 'utf8'),
          new Buffer(this.oidc.bearer, 'utf8'),
          1000
        );
        this.assert(valid, new errors.InvalidTokenError());
        break;
      }
      default:
    }

    yield next;
  }

  function* validateRegistrationAccessToken(next) {
    const regAccessToken = yield RegistrationAccessToken.find(this.oidc.bearer);
    this.assert(regAccessToken, new errors.InvalidTokenError());

    const client = yield provider.Client.find(this.params.clientId);

    if (!client || client.clientId !== regAccessToken.clientId) {
      yield regAccessToken.destroy();
      this.throw(new errors.InvalidTokenError());
    }

    this.oidc.client = client;

    yield next;
  }

  return {
    post: compose([
      noCache,
      parseBody,
      validateInitialAccessToken,
      function* registrationResponse() {
        const properties = {};
        const clientId = uuid.v4();

        const rat = new RegistrationAccessToken({ clientId });

        Object.assign(properties, this.request.body, {
          client_id: clientId,
          client_id_issued_at: epochTime(),
        });

        const Client = provider.Client;
        const secretRequired = Client.needsSecret(properties);

        if (secretRequired) {
          Object.assign(properties, {
            client_secret: crypto.randomBytes(48).toString('base64'),
            client_secret_expires_at: 0,
          });
        }

        const client = yield provider.addClient(properties, true);

        this.body = client.metadata();

        Object.assign(this.body, {
          registration_client_uri: this.oidc.urlFor('registration_client', {
            clientId: properties.client_id,
          }),
          registration_access_token: yield rat.save(),
        });

        this.status = 201;

        provider.emit('registration_create.success', client, this);
      },
    ]),

    get: compose([
      noCache,
      validateRegistrationAccessToken,

      function* clientReadResponse(next) {
        this.body = this.oidc.client.metadata();

        Object.assign(this.body, {
          registration_access_token: this.oidc.bearer,
          registration_client_uri: this.oidc.urlFor('registration_client', {
            clientId: this.params.clientId,
          }),
        });

        yield next;
      },
    ]),

    put: compose([
      noCache,
      validateRegistrationAccessToken,
      parseBody,

      function* forbiddenFields(next) {
        const hit = FORBIDDEN.find(field => this.request.body[field] !== undefined);

        this.assert(!hit, new errors.InvalidRequestError(
          `request MUST NOT include the "${hit}" field`));

        yield next;
      },

      function* metaChecks(next) {
        const hit = _.findKey(this.oidc.client.metadata(), findMissingKey.bind(this));

        this.assert(!hit, new errors.InvalidRequestError(`${hit} must be provided`));
        yield next;
      },

      function* equalChecks(next) {
        this.assert(this.request.body.client_id === this.oidc.client.clientId,
          new errors.InvalidRequestError('provided client_id is not right')); // TODO: msg

        if (this.request.body.client_secret) {
          const clientSecretValid = bufferEqualsConstant(
            new Buffer(this.request.body.client_secret, 'utf8'),
            new Buffer(this.oidc.client.clientSecret, 'utf8'),
            1000
          );
          this.assert(clientSecretValid,
            new errors.InvalidRequestError('provided client_secret is not right')); // TODO: msg
        }

        yield next;
      },

      function* clientUpdateResponse(next) {
        if (this.oidc.client.noManage) {
          throw new errors.InvalidRequestError('this client is not allowed to update its records',
            403);
        }

        provider.emit('registration_update.success', this.oidc.client, this);

        const properties = {};

        Object.assign(properties, this.request.body, {
          client_id: this.oidc.client.clientId,
          client_id_issued_at: this.oidc.client.clientIdIssuedAt,
        });

        const Client = provider.Client;
        const secretRequired = !this.oidc.client.clientSecret && Client.needsSecret(properties);

        if (secretRequired) {
          Object.assign(properties, {
            client_secret: crypto.randomBytes(48).toString('base64'),
            client_secret_expires_at: 0,
          });
        } else {
          Object.assign(properties, {
            client_secret: this.oidc.client.clientSecret,
            client_secret_expires_at: this.oidc.client.clientSecretExpiresAt,
          });
        }

        const client = yield provider.addClient(properties, true);

        this.body = client.metadata();

        Object.assign(this.body, {
          registration_access_token: this.oidc.bearer,
          registration_client_uri: this.oidc.urlFor('registration_client', {
            clientId: this.params.clientId,
          }),
        });

        yield next;
      },
    ]),

    delete: compose([
      noCache,
      validateRegistrationAccessToken,

      function* clientRemoveResponse(next) {
        if (this.oidc.client.noManage) {
          throw new errors.InvalidRequestError('this client is not allowed to delete itself', 403);
        }

        yield provider.Client.remove(this.oidc.client.clientId);

        this.status = 204;

        provider.emit('registration_delete.success', this.oidc.client, this);

        yield next;
      },
    ]),
  };
};
