const compose = require('koa-compose');
const constantEquals = require('../helpers/constant_equals');
const crypto = require('crypto');
const uuid = require('uuid/v4');
const assert = require('assert');
const { has, findKey, chain } = require('lodash');

const noCache = require('../shared/no_cache');
const bodyParser = require('../shared/selective_body');

const epochTime = require('../helpers/epoch_time');
const { InvalidToken, InvalidRequest } = require('../helpers/errors');
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

function defaultSecretFactory() {
  return crypto.randomBytes(48).toString('base64');
}

module.exports = function registrationAction(provider) {
  const idFactory = instance(provider).configuration('features.registration.idFactory') || uuid;
  const secretFactory = instance(provider).configuration('features.registration.secretFactory') || defaultSecretFactory;
  assert.equal(typeof idFactory, 'function', 'idFactory must be a function');
  assert.equal(typeof secretFactory, 'function', 'secretFactory must be a function');

  async function validateInitialAccessToken(ctx, next) {
    const registration = instance(provider).configuration('features.registration');
    switch (registration.initialAccessToken && typeof registration.initialAccessToken) {
      case 'boolean': {
        const initialAccessToken = await provider.InitialAccessToken.find(ctx.oidc.bearer);
        ctx.assert(initialAccessToken, new InvalidToken());
        ctx.oidc.entity('InitialAccessToken', initialAccessToken);
        break;
      }
      case 'string': {
        const valid = constantEquals(
          registration.initialAccessToken,
          ctx.oidc.bearer,
          1000,
        );
        ctx.assert(valid, new InvalidToken());
        break;
      }
      default:
    }

    await next();
  }

  async function validateRegistrationAccessToken(ctx, next) {
    const regAccessToken = await provider.RegistrationAccessToken.find(ctx.oidc.bearer);
    ctx.assert(regAccessToken, new InvalidToken());

    const client = await provider.Client.find(ctx.params.clientId, {
      fresh: true,
    });

    if (!client || client.clientId !== regAccessToken.clientId) {
      await regAccessToken.destroy();
      ctx.throw(new InvalidToken());
    }

    ctx.oidc.entity('Client', client);
    ctx.oidc.entity('RegistrationAccessToken', regAccessToken);

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
            client_secret: secretFactory(), client_secret_expires_at: 0,
          });
        }

        const client = await instance(provider).clientAdd(properties, true);
        ctx.oidc.entity('Client', client);

        ctx.body = client.metadata();

        Object.assign(ctx.body, {
          registration_client_uri: ctx.oidc.urlFor('client', {
            clientId: properties.client_id,
          }),
          registration_access_token: await rat.save(),
        });

        ctx.oidc.entity('RegistrationAccessToken', rat);

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
          registration_client_uri: ctx.oidc.urlFor('client', {
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
        ctx.assert(!hit, new InvalidRequest(`request MUST NOT include the "${hit}" field`));
        await next();
      },

      async function metaChecks(ctx, next) {
        const hit = findKey(ctx.oidc.client.metadata(), findMissingKey.bind(ctx));
        ctx.assert(!hit, new InvalidRequest(`${hit} must be provided`));
        await next();
      },

      async function equalChecks(ctx, next) {
        ctx.assert(ctx.oidc.body.client_id === ctx.oidc.client.clientId, new InvalidRequest('provided client_id does not match the authenticated client\'s one'));

        if (ctx.oidc.body.client_secret) {
          const clientSecretValid = constantEquals(
            ctx.oidc.body.client_secret,
            ctx.oidc.client.clientSecret,
            1000,
          );

          ctx.assert(clientSecretValid, new InvalidRequest('provided client_secret does not match the authenticated client\'s one'));
        }

        await next();
      },

      async function clientUpdateResponse(ctx, next) {
        if (ctx.oidc.client.noManage) {
          throw new InvalidRequest('this client is not allowed to update its records', 403);
        }

        const properties = chain({}).defaults({
          client_id: ctx.oidc.client.clientId,
          client_id_issued_at: ctx.oidc.client.clientIdIssuedAt,
        })
          .defaults(ctx.oidc.body)
          .omitBy(value => value === null || value === '')
          .value();

        const { Client } = provider;
        const secretRequired = !ctx.oidc.client.clientSecret && Client.needsSecret(properties);

        // TODO: support for expiring dynamic registration clients
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
          registration_client_uri: ctx.oidc.urlFor('client', {
            clientId: ctx.params.clientId,
          }),
        });

        const management = instance(provider).configuration('features.registrationManagement');
        if (management.rotateRegistrationAccessToken) {
          ctx.oidc.entity('RotatedRegistrationAccessToken', ctx.oidc.entities.RegistrationAccessToken);
          const rat = new provider.RegistrationAccessToken({ clientId: ctx.oidc.client.clientId });

          await ctx.oidc.registrationAccessToken.destroy();

          ctx.body.registration_access_token = await rat.save();
          ctx.oidc.entity('RegistrationAccessToken', rat);
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
          throw new InvalidRequest('this client is not allowed to delete itself', 403);
        }

        await instance(provider).clientRemove(ctx.oidc.client.clientId);

        ctx.status = 204;

        provider.emit('registration_delete.success', ctx.oidc.client, ctx);

        await next();
      },
    ]),
  };
};
