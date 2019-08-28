const omitBy = require('lodash/omitBy');
const findKey = require('lodash/findKey');
const has = require('lodash/has');

const constantEquals = require('../helpers/constant_equals');
const noCache = require('../shared/no_cache');
const { json: parseBody } = require('../shared/selective_body');
const epochTime = require('../helpers/epoch_time');
const { InvalidToken, InvalidRequest } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const setWWWAuthenticate = require('../helpers/set_www_authenticate');

const FORBIDDEN = [
  'registration_access_token',
  'registration_client_uri',
  'client_secret_expires_at',
  'client_id_issued_at',
];

function findMissingKey(value, key) {
  return !FORBIDDEN.includes(key) && !has(this.oidc.body, key) && value !== undefined;
}

async function setWWWAuthenticateHeader(ctx, next) {
  try {
    await next();
  } catch (err) {
    if (err.expose) {
      setWWWAuthenticate(ctx, 'Bearer', {
        realm: ctx.oidc.issuer,
        ...(err.error_description !== 'no access token provided' ? {
          error: err.message,
          error_description: err.error_description,
        } : undefined),
      });
    }
    throw err;
  }
}

const validateRegistrationAccessToken = [
  setWWWAuthenticateHeader,
  async function validateRegistrationAccessToken(ctx, next) {
    const regAccessToken = await ctx.oidc.provider.RegistrationAccessToken.find(
      ctx.oidc.getAccessToken(),
    );
    ctx.assert(regAccessToken, new InvalidToken('token not found'));

    const client = await ctx.oidc.provider.Client.find(ctx.params.clientId);

    if (!client || client.clientId !== regAccessToken.clientId) {
      await regAccessToken.destroy();
      throw new InvalidToken('authenticated client and registration access token client mismatch');
    }

    ctx.oidc.entity('Client', client);
    ctx.oidc.entity('RegistrationAccessToken', regAccessToken);

    await next();
  },
];

module.exports = {
  post: [
    noCache,
    setWWWAuthenticateHeader,
    parseBody,
    async function validateInitialAccessToken(ctx, next) {
      const { oidc: { provider } } = ctx;
      const { initialAccessToken } = instance(provider).configuration('features.registration');
      switch (initialAccessToken && typeof initialAccessToken) {
        case 'boolean': {
          const iat = await provider.InitialAccessToken.find(ctx.oidc.getAccessToken());
          ctx.assert(iat, new InvalidToken('initial access token not found'));
          ctx.oidc.entity('InitialAccessToken', iat);
          break;
        }
        case 'string': {
          const valid = constantEquals(
            initialAccessToken,
            ctx.oidc.getAccessToken(),
            1000,
          );
          ctx.assert(valid, new InvalidToken('invalid initial access token value'));
          break;
        }
        default:
      }

      await next();
    },
    async function registrationResponse(ctx, next) {
      const { oidc: { provider } } = ctx;
      const { idFactory, secretFactory } = instance(provider).configuration('features.registration');
      const properties = {};
      const clientId = idFactory();

      const rat = new provider.RegistrationAccessToken({ clientId });
      ctx.oidc.entity('RegistrationAccessToken', rat);

      Object.assign(properties, ctx.oidc.body, {
        client_id: clientId,
        client_id_issued_at: epochTime(),
      });

      const { Client } = provider;
      const secretRequired = Client.needsSecret(properties);

      if (secretRequired) {
        Object.assign(properties, {
          client_secret: secretFactory(),
          client_secret_expires_at: 0,
        });
      } else {
        Object.assign(properties, {
          client_secret: undefined,
          client_secret_expires_at: undefined,
        });
      }

      if (
        ctx.oidc.entities.InitialAccessToken
        && ctx.oidc.entities.InitialAccessToken.policies
      ) {
        const { policies } = ctx.oidc.entities.InitialAccessToken;
        const implementations = instance(provider).configuration('features.registration.policies');
        for (const policy of policies) { // eslint-disable-line no-restricted-syntax
          await implementations[policy](ctx, properties); // eslint-disable-line no-await-in-loop
        }

        if (!('policies' in rat)) {
          rat.policies = policies;
        }
      }

      const client = await instance(provider).clientAdd(properties, { store: true, ctx });
      ctx.oidc.entity('Client', client);

      ctx.body = client.metadata();

      Object.assign(ctx.body, {
        registration_client_uri: ctx.oidc.urlFor('client', {
          clientId: properties.client_id,
        }),
        registration_access_token: await rat.save(),
      });

      ctx.status = 201;

      provider.emit('registration_create.success', ctx, client);

      await next();
    },
  ],

  get: [
    noCache,
    ...validateRegistrationAccessToken,

    async function clientReadResponse(ctx, next) {
      if (ctx.oidc.client.noManage) {
        throw new InvalidRequest('client does not have permission to read its record', 403);
      }

      ctx.body = ctx.oidc.client.metadata();

      Object.assign(ctx.body, {
        registration_access_token: ctx.oidc.getAccessToken(),
        registration_client_uri: ctx.oidc.urlFor('client', {
          clientId: ctx.params.clientId,
        }),
      });

      await next();
    },
  ],

  put: [
    noCache,
    ...validateRegistrationAccessToken,
    parseBody,

    async function forbiddenFields(ctx, next) {
      const hit = FORBIDDEN.find((field) => ctx.oidc.body[field] !== undefined);
      ctx.assert(!hit, new InvalidRequest(`request MUST NOT include the ${hit} field`));
      await next();
    },

    async function metaChecks(ctx, next) {
      const hit = findKey(ctx.oidc.client.metadata(), findMissingKey.bind(ctx));
      ctx.assert(!hit, new InvalidRequest(`${hit} must be provided`));
      await next();
    },

    async function equalChecks(ctx, next) {
      ctx.assert(ctx.oidc.body.client_id === ctx.oidc.client.clientId, new InvalidRequest('provided client_id does not match the authenticated client\'s one'));

      if ('client_secret' in ctx.oidc.body) {
        const clientSecretValid = constantEquals(
          typeof ctx.oidc.body.client_secret === 'string' ? ctx.oidc.body.client_secret : '',
          ctx.oidc.client.clientSecret || '',
          1000,
        );

        ctx.assert(clientSecretValid, new InvalidRequest('provided client_secret does not match the authenticated client\'s one'));
      }

      await next();
    },

    async function clientUpdateResponse(ctx, next) {
      if (ctx.oidc.client.noManage) {
        throw new InvalidRequest('client does not have permission to update its record', 403);
      }

      const properties = omitBy({
        client_id: ctx.oidc.client.clientId,
        client_id_issued_at: ctx.oidc.client.clientIdIssuedAt,
        ...ctx.oidc.body,
      }, (value) => value === null || value === '');

      const { oidc: { provider } } = ctx;
      const { secretFactory } = instance(provider).configuration('features.registration');

      const secretRequired = !ctx.oidc.client.clientSecret
        && provider.Client.needsSecret(properties);

      if (secretRequired) {
        Object.assign(properties, {
          client_secret: secretFactory(),
          client_secret_expires_at: 0,
        });
      } else {
        Object.assign(properties, {
          client_secret: ctx.oidc.client.clientSecret,
          client_secret_expires_at: ctx.oidc.client.clientSecretExpiresAt,
        });
      }

      if (ctx.oidc.entities.RegistrationAccessToken.policies) {
        const { policies } = ctx.oidc.entities.RegistrationAccessToken;
        const implementations = instance(provider).configuration('features.registration.policies');
        for (const policy of policies) { // eslint-disable-line no-restricted-syntax
          await implementations[policy](ctx, properties); // eslint-disable-line no-await-in-loop
        }
      }

      const client = await instance(provider).clientAdd(properties, { store: true, ctx });

      ctx.body = client.metadata();

      Object.assign(ctx.body, {
        registration_access_token: ctx.oidc.getAccessToken(),
        registration_client_uri: ctx.oidc.urlFor('client', {
          clientId: ctx.params.clientId,
        }),
      });

      const management = instance(provider).configuration('features.registrationManagement');
      if (
        management.rotateRegistrationAccessToken === true
        || (typeof management.rotateRegistrationAccessToken === 'function' && await management.rotateRegistrationAccessToken(ctx))
      ) {
        ctx.oidc.entity('RotatedRegistrationAccessToken', ctx.oidc.entities.RegistrationAccessToken);
        const rat = new provider.RegistrationAccessToken({
          client: ctx.oidc.client,
          policies: ctx.oidc.entities.RegistrationAccessToken.policies,
        });

        await ctx.oidc.registrationAccessToken.destroy();

        ctx.oidc.entity('RegistrationAccessToken', rat);
        ctx.body.registration_access_token = await rat.save();
      }

      provider.emit('registration_update.success', ctx, ctx.oidc.client);

      await next();
    },
  ],

  delete: [
    noCache,
    ...validateRegistrationAccessToken,

    async function clientRemoveResponse(ctx, next) {
      if (ctx.oidc.client.noManage) {
        throw new InvalidRequest('client does not have permission to delete its record', 403);
      }

      const { oidc: { provider } } = ctx;

      await instance(provider).clientRemove(ctx.oidc.client.clientId);

      ctx.status = 204;

      provider.emit('registration_delete.success', ctx, ctx.oidc.client);

      await next();
    },
  ],
};
