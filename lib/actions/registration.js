const { has, findKey } = require('lodash');
const compose = require('koa-compose');
const constantEquals = require('buffer-equals-constant');
const crypto = require('crypto');
const uuid = require('uuid');
const assert = require('assert');

const noCache = require('../shared/no_cache');
const bodyParser = require('../shared/selective_body');

const epochTime = require('../helpers/epoch_time');
const { InvalidTokenError, InvalidRequestError } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const parseBody = bodyParser('application/json');

const FORBIDDEN = [
  'registration_access_token',
  'registration_client_uri',
  'client_secret_expires_at',
  'client_id_issued_at',
];

function findMissingKey(value, key) {
  return !FORBIDDEN.includes(key) && !has(this.oidc.body, key) && value !== undefined;
}

module.exports = function registrationAction(provider) {
  const idFactory = instance(provider).configuration('features.registration.idFactory') || uuid;
  assert.equal(typeof idFactory, 'function', 'idFactory must be a function');

  async function validateInitialAccessToken(ctx, next) {
    const registration = instance(provider).configuration('features.registration');
    switch (registration.initialAccessToken && typeof registration.initialAccessToken) {
      case 'boolean': {
        const initialAccessToken = await provider.InitialAccessToken.find(ctx.oidc.bearer);
        ctx.assert(initialAccessToken, new InvalidTokenError());
        break;
      }
      case 'string': {
        const valid = constantEquals(
          Buffer.from(registration.initialAccessToken, 'utf8'),
          Buffer.from(ctx.oidc.bearer, 'utf8'),
          1000,
        );
        ctx.assert(valid, new InvalidTokenError());
        break;
      }
      default:
    }

    await next();
  }

  async function validateRegistrationAccessToken(ctx, next) {
    const regAccessToken = await provider.RegistrationAccessToken.find(ctx.oidc.bearer);
    ctx.assert(regAccessToken, new InvalidTokenError());

    const client = await provider.Client.find(ctx.params.clientId, {
      fresh: true,
    });

    if (!client || client.clientId !== regAccessToken.clientId) {
      await regAccessToken.destroy();
      ctx.throw(new InvalidTokenError());
    }

    ctx.oidc.client = client;
    ctx.oidc.registrationAccessToken = regAccessToken;

    await next();
  }

  return {
    post: compose([
      noCache,
      parseBody,
      validateInitialAccessToken,
      async function registrationResponse(ctx, next) {
        const properties = {};
        const clientId = String(idFactory());

        const rat = new provider.RegistrationAccessToken({ clientId });

        Object.assign(properties, ctx.oidc.body, {
          client_id: clientId,
          client_id_issued_at: epochTime(),
        });

        const { Client } = provider;
        const secretRequired = Client.needsSecret(properties);

        if (secretRequired) {
          Object.assign(properties, {
            client_secret: crypto.randomBytes(48).toString('base64'), client_secret_expires_at: 0,
          });
        }

        const client = await instance(provider).clientAdd(properties, true);

        ctx.body = client.metadata();

        Object.assign(ctx.body, {
          registration_client_uri: ctx.oidc.urlFor('registration_client', {
            clientId: properties.client_id,
          }),
          registration_access_token: await rat.save(),
        });

        ctx.status = 201;

        provider.emit('registration_create.success', client, ctx);

        await next();
      },
    ]),

    get: compose([
      noCache,
      validateRegistrationAccessToken,

      async function clientReadResponse(ctx, next) {
        ctx.body = ctx.oidc.client.metadata();

        Object.assign(ctx.body, {
          registration_access_token: ctx.oidc.bearer,
          registration_client_uri: ctx.oidc.urlFor('registration_client', {
            clientId: ctx.params.clientId,
          }),
        });

        await next();
      },
    ]),

    put: compose([
      noCache,
      validateRegistrationAccessToken,
      parseBody,

      async function forbiddenFields(ctx, next) {
        const hit = FORBIDDEN.find(field => ctx.oidc.body[field] !== undefined);
        ctx.assert(!hit, new InvalidRequestError(`request MUST NOT include the "${hit}" field`));
        await next();
      },

      async function metaChecks(ctx, next) {
        const hit = findKey(ctx.oidc.client.metadata(), findMissingKey.bind(ctx));
        ctx.assert(!hit, new InvalidRequestError(`${hit} must be provided`));
        await next();
      },

      async function equalChecks(ctx, next) {
        ctx.assert(ctx.oidc.body.client_id === ctx.oidc.client.clientId, new InvalidRequestError('provided client_id does not match the authenticated client\'s one'));

        if (ctx.oidc.body.client_secret) {
          const clientSecretValid = constantEquals(
            Buffer.from(ctx.oidc.body.client_secret, 'utf8'),
            Buffer.from(ctx.oidc.client.clientSecret, 'utf8'),
            1000,
          );

          ctx.assert(clientSecretValid, new InvalidRequestError('provided client_secret does not match the authenticated client\'s one'));
        }

        await next();
      },

      async function clientUpdateResponse(ctx, next) {
        if (ctx.oidc.client.noManage) {
          throw new InvalidRequestError(
            'this client is not allowed to update its records',
            403,
          );
        }

        const properties = {};

        Object.assign(properties, ctx.oidc.body, {
          client_id: ctx.oidc.client.clientId,
          client_id_issued_at: ctx.oidc.client.clientIdIssuedAt,
        });

        const { Client } = provider;
        const secretRequired = !ctx.oidc.client.clientSecret && Client.needsSecret(properties);

        if (secretRequired) {
          Object.assign(properties, {
            client_secret: crypto.randomBytes(48).toString('base64'),
            client_secret_expires_at: 0,
          });
        } else {
          Object.assign(properties, {
            client_secret: ctx.oidc.client.clientSecret,
            client_secret_expires_at: ctx.oidc.client.clientSecretExpiresAt,
          });
        }

        const client = await instance(provider).clientAdd(properties, true);

        ctx.body = client.metadata();

        Object.assign(ctx.body, {
          registration_access_token: ctx.oidc.bearer,
          registration_client_uri: ctx.oidc.urlFor('registration_client', {
            clientId: ctx.params.clientId,
          }),
        });

        const management = instance(provider).configuration('features.registrationManagement');
        if (management.rotateRegistrationAccessToken) {
          const rat = new provider.RegistrationAccessToken({ clientId: ctx.oidc.client.clientId });

          await ctx.oidc.registrationAccessToken.destroy();
          ctx.oidc.registrationAccessToken = rat;

          ctx.body.registration_access_token = await rat.save();
        }

        provider.emit('registration_update.success', ctx.oidc.client, ctx);

        await next();
      },
    ]),

    delete: compose([
      noCache,
      validateRegistrationAccessToken,

      async function clientRemoveResponse(ctx, next) {
        if (ctx.oidc.client.noManage) {
          throw new InvalidRequestError('this client is not allowed to delete itself', 403);
        }

        await instance(provider).clientRemove(ctx.oidc.client.clientId);

        ctx.status = 204;

        provider.emit('registration_delete.success', ctx.oidc.client, ctx);

        await next();
      },
    ]),
  };
};
