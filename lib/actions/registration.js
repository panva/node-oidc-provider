import omitBy from '../helpers/_/omit_by.js';
import constantEquals from '../helpers/constant_equals.js';
import noCache from '../shared/no_cache.js';
import { json as parseBody } from '../shared/selective_body.js';
import epochTime from '../helpers/epoch_time.js';
import { InvalidToken, InvalidRequest } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import appendWWWAuthenticate from '../helpers/append_www_authenticate.js';
import addClient from '../helpers/add_client.js';

const FORBIDDEN = [
  'registration_access_token',
  'registration_client_uri',
  'client_secret_expires_at',
  'client_id_issued_at',
];

async function validateRegistrationAccessToken(ctx, next) {
  try {
    const regAccessToken = await ctx.oidc.provider.RegistrationAccessToken.find(
      ctx.oidc.getAccessToken(),
    );
    ctx.assert(regAccessToken, new InvalidToken('registration access token not found'));

    const client = await ctx.oidc.provider.Client.find(ctx.params.clientId);

    if (client?.clientId !== regAccessToken.clientId) {
      await regAccessToken.destroy();
      throw new InvalidToken('client mismatch');
    }

    ctx.oidc.entity('Client', client);
    ctx.oidc.entity('RegistrationAccessToken', regAccessToken);
  } catch (err) {
    if (err.expose) {
      if (err.error_description === 'no access token provided') {
        appendWWWAuthenticate(ctx, 'Bearer', {
          realm: ctx.oidc.issuer,
          scope: err.scope,
        });
      } else {
        appendWWWAuthenticate(ctx, 'Bearer', {
          realm: ctx.oidc.issuer,
          error: err.message,
          error_description: err.error_description,
        });
      }
    }
    throw err;
  }

  await next();
}

export const post = [
  noCache,
  parseBody,
  async function validateInitialAccessToken(ctx, next) {
    try {
      const { oidc: { provider } } = ctx;
      const { initialAccessToken } = instance(provider).features.registration;
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
    } catch (err) {
      if (err.expose) {
        if (err.error_description === 'no access token provided') {
          appendWWWAuthenticate(ctx, 'Bearer', {
            realm: ctx.oidc.issuer,
            scope: err.scope,
          });
        } else {
          appendWWWAuthenticate(ctx, 'Bearer', {
            realm: ctx.oidc.issuer,
            error: err.message,
            error_description: err.error_description,
          });
        }
      }
      throw err;
    }

    await next();
  },
  async function registrationResponse(ctx) {
    const { oidc: { provider } } = ctx;
    const {
      idFactory, secretFactory, issueRegistrationAccessToken,
    } = instance(provider).features.registration;
    const properties = {};
    const clientId = idFactory(ctx);

    let rat;

    if (
      issueRegistrationAccessToken === true
      || (typeof issueRegistrationAccessToken === 'function' && issueRegistrationAccessToken(ctx))
    ) {
      rat = new provider.RegistrationAccessToken({ clientId });
      ctx.oidc.entity('RegistrationAccessToken', rat);
    }

    Object.assign(properties, ctx.oidc.body, {
      client_id: clientId,
      client_id_issued_at: epochTime(),
    });

    const { Client } = provider;
    const secretRequired = Client.needsSecret(properties);

    if (secretRequired) {
      Object.assign(properties, {
        client_secret: await secretFactory(ctx),
        client_secret_expires_at: 0,
      });
    } else {
      delete properties.client_secret;
      delete properties.client_secret_expires_at;
    }

    if (
      ctx.oidc.entities.InitialAccessToken?.policies
    ) {
      const { policies } = ctx.oidc.entities.InitialAccessToken;
      const implementations = instance(provider).features.registration.policies;
      for (const policy of policies) {
        await implementations[policy](ctx, properties);
      }

      if (rat && !('policies' in rat)) {
        rat.policies = policies;
      }
    }

    const client = await addClient(provider, properties, { store: true, ctx });
    ctx.oidc.entity('Client', client);

    ctx.body = client.metadata();

    if (rat) {
      Object.assign(ctx.body, {
        registration_client_uri: ctx.oidc.urlFor('client', {
          clientId: properties.client_id,
        }),
        registration_access_token: await rat.save(),
      });
    }

    ctx.status = 201;

    provider.emit('registration_create.success', ctx, client);
  },
];

export const get = [
  noCache,
  validateRegistrationAccessToken,

  async function clientReadResponse(ctx) {
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
  },
];

export const put = [
  noCache,
  validateRegistrationAccessToken,
  parseBody,

  async function forbiddenFields(ctx, next) {
    const hit = FORBIDDEN.find((field) => ctx.oidc.body[field] !== undefined);
    ctx.assert(!hit, new InvalidRequest(`request MUST NOT include the ${hit} field`));
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

  async function clientUpdateResponse(ctx) {
    if (ctx.oidc.client.noManage) {
      throw new InvalidRequest('client does not have permission to update its record', 403);
    }

    const properties = omitBy({
      client_id: ctx.oidc.client.clientId,
      client_id_issued_at: ctx.oidc.client.clientIdIssuedAt,
      ...ctx.oidc.body,
    }, (value) => value === null || value === '');

    const { oidc: { provider } } = ctx;
    const { secretFactory } = instance(provider).features.registration;

    const secretRequired = !ctx.oidc.client.clientSecret
      && provider.Client.needsSecret(properties);

    if (secretRequired) {
      Object.assign(properties, {
        client_secret: await secretFactory(ctx),
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
      const implementations = instance(provider).features.registration.policies;
      for (const policy of policies) {
        await implementations[policy](ctx, properties);
      }
    }

    const client = await addClient(provider, properties, { store: true, ctx });

    ctx.body = client.metadata();

    Object.assign(ctx.body, {
      registration_access_token: ctx.oidc.getAccessToken(),
      registration_client_uri: ctx.oidc.urlFor('client', {
        clientId: ctx.params.clientId,
      }),
    });

    const management = instance(provider).features.registrationManagement;
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
  },
];

export const del = [
  noCache,
  validateRegistrationAccessToken,

  async function clientRemoveResponse(ctx) {
    if (ctx.oidc.client.noManage) {
      throw new InvalidRequest('client does not have permission to delete its record', 403);
    }

    const { oidc: { provider } } = ctx;

    await provider.Client.adapter.destroy(ctx.oidc.client.clientId);
    await ctx.oidc.entities.RegistrationAccessToken.destroy();

    ctx.status = 204;

    provider.emit('registration_delete.success', ctx, ctx.oidc.client);
  },
];
