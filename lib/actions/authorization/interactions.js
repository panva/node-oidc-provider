const url = require('url');
const _ = require('lodash');
const { InvalidRequest } = require('../../helpers/errors');
const mask = require('../../helpers/claims');
const instance = require('../../helpers/weak_cache');
const debug = require('debug')('oidc-provider:authentication:interrupted');

module.exports = (provider) => {
  const Claims = mask(instance(provider).configuration());
  const interactionCheck = instance(provider).configuration('interactionCheck');

  const interactionChecks = [
    // no account id was found in the session info
    (ctx) => {
      if (!ctx.oidc.session.accountId()) {
        return {
          error: 'login_required',
          error_description: 'End-User authentication is required',
          reason: 'no_session',
          reason_description: 'Please Sign-in to continue.',
        };
      }
      return false;
    },

    // login was requested by the client by prompt parameter
    (ctx) => {
      if (ctx.oidc.promptPending('login')) {
        return {
          error: 'login_required',
          error_description: 'End-User authentication could not be obtained',
          reason: 'login_prompt',
          reason_description: `${ctx.oidc.client.name || ctx.oidc.client.clientId} asks you to Sign-in again.`,
        };
      }
      return false;
    },

    // session is too old for this authorization request
    (ctx) => {
      if (ctx.oidc.session.past(ctx.oidc.params.max_age)) {
        return {
          error: 'login_required',
          error_description: 'End-User re-authentication could not be obtained',
          reason: 'max_age',
          reason_description: `${ctx.oidc.client.name || ctx.oidc.client.clientId} asks you to Sign-in again.`,
        };
      }
      return false;
    },

    // session subject value differs from the one requested
    (ctx) => {
      if (_.has(ctx.oidc.claims, 'id_token.sub.value')) {
        const subject = Claims.sub(ctx.oidc.session.accountId(), ctx.oidc.client.sectorIdentifier);
        if (ctx.oidc.claims.id_token.sub.value !== subject) {
          return {
            error: 'login_required',
            error_description: 'requested subject could not be obtained',
            reason: 'claims_id_token_sub_value',
            reason_description: `${ctx.oidc.client.name || ctx.oidc.client.clientId} asks you to Sign-in with a specific identity.`,
          };
        }
      }
      return false;
    },

    // none of multiple authentication context class references requested are met
    (ctx) => {
      const request = _.get(ctx.oidc.claims, 'id_token.acr', {});
      if (request && request.essential && request.values) {
        if (!request.values.includes(ctx.oidc.acr)) {
          return {
            error: 'login_required',
            error_description: 'none of the requested ACRs could not be obtained',
            reason: 'essential_acrs',
            reason_description: `${ctx.oidc.client.name || ctx.oidc.client.clientId} asks you to Sign-in using a specific method.`,
          };
        }
      }
      return false;
    },

    // single requested authentication context class reference is not met
    (ctx) => {
      const request = _.get(ctx.oidc.claims, 'id_token.acr', {});
      if (request && request.essential && request.value) {
        if (request.value !== ctx.oidc.acr) {
          return {
            error: 'login_required',
            error_description: 'requested ACR could not be obtained',
            reason: 'essential_acr',
            reason_description: `${ctx.oidc.client.name || ctx.oidc.client.clientId} asks you to Sign-in using a specific method.`,
          };
        }
      }
      return false;
    },

    // any unfulfilled prompts other than none or login
    (ctx) => {
      const missed = _.find(ctx.oidc.prompts, (prompt) => {
        if (prompt !== 'none' && ctx.oidc.promptPending(prompt)) {
          return true;
        }
        return false;
      });

      if (missed) {
        return {
          error: missed === 'consent' ? 'consent_required' : 'interaction_required',
          error_description: `prompt ${missed} was not resolved`,
          reason: `${missed}_prompt`,
        };
      }

      return false;
    },

    async (ctx) => {
      const hint = ctx.oidc.params.id_token_hint;
      if (hint !== undefined) {
        const { client } = ctx.oidc;
        const actualSub = Claims.sub(ctx.oidc.session.accountId(), client.sectorIdentifier);
        const { IdToken } = provider;

        const decoded = await IdToken.validate(hint, client).catch((err) => {
          throw new InvalidRequest(`could not validate id_token_hint (${err.message})`);
        });

        if (decoded.payload.sub !== actualSub) {
          return {
            error: 'login_required',
            error_description: 'id_token_hint and authenticated subject do not match',
            reason: 'id_token_hint',
            reason_description: `${client.name || client.clientId} asks that you Sign-in with a specific identity.`,
          };
        }
      }

      return false;
    },

    interactionCheck,
  ];

  return async function interactions(ctx, next) {
    let interaction;

    // interaction checks are intended to run sequential and some are async
    for (const fn of interactionChecks) { // eslint-disable-line no-restricted-syntax
      interaction = await fn(ctx); // eslint-disable-line no-await-in-loop
      if (interaction) break;
    }

    if (interaction) {
      _.defaults(interaction, {
        error: 'interaction_required',
        error_description: 'interaction is required from the end-user',
      });

      // if interaction needed but prompt=none => throw;
      try {
        if (ctx.oidc.promptPending('none')) {
          ctx.throw(interaction.error, {
            error_description: interaction.error_description,
          });
        }
      } catch (err) {
        err.status = 302;
        err.statusCode = 302;
        err.expose = true;
        throw err;
      }

      const destination = await instance(provider).configuration('interactionUrl')(ctx, interaction);
      const cookieOptions = instance(provider).configuration('cookies.short');
      const returnTo = ctx.oidc.urlFor('resume', { grant: ctx.oidc.uuid });

      const interactionSession = new provider.Session(ctx.oidc.uuid, {
        returnTo,
        interaction,
        accountId: ctx.oidc.session.accountId(),
        uuid: ctx.oidc.uuid,
        params: ctx.oidc.params.toPlainObject(),
        signed: ctx.oidc.signed,
      });

      await interactionSession.save(cookieOptions.maxAge / 1000);

      ctx.cookies.set(
        provider.cookieName('interaction'), ctx.oidc.uuid,
        { path: url.parse(destination).pathname, ...cookieOptions },
      );

      ctx.cookies.set(
        provider.cookieName('resume'), ctx.oidc.uuid,
        { path: url.parse(returnTo).pathname, ...cookieOptions },
      );

      debug('uuid=%s interaction=%o', ctx.oidc.uuid, interaction);
      provider.emit('interaction.started', interaction, ctx);
      ctx.redirect(destination);
    } else {
      await next();
    }
  };
};
