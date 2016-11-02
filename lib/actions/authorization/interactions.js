'use strict';

const url = require('url');
const _ = require('lodash');
const errors = require('../../helpers/errors');
const mask = require('../../helpers/claims');
const instance = require('../../helpers/weak_cache');

const j = JSON.stringify;

module.exports = (provider) => {
  const Claims = mask(instance(provider).configuration());

  return function* interactions(next) {
    const ctx = this.oidc;
    const clientName = _.get(ctx.client, 'name', 'Client');

    const interactionChecks = [

      // no account id was found in the session info
      () => {
        if (!ctx.session.accountId()) {
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
      () => {
        if (ctx.prompted('login')) {
          return {
            error: 'login_required',
            error_description: 'End-User authentication could not be obtained',
            reason: 'login_prompt',
            reason_description: `${clientName} asks you to Sign-in again.`,
          };
        }
        return false;
      },

      // session is too old for this authorization request
      () => {
        if (ctx.session.past(ctx.params.max_age)) {
          return {
            error: 'login_required',
            error_description: 'End-User re-authentication could not be obtained',
            reason: 'max_age',
            reason_description: `${clientName} asks you to Sign-in again.`,
          };
        }
        return false;
      },

      // session subject value differs from the one requested
      () => {
        if (_.has(ctx.claims, 'id_token.sub.value')) {
          const subject = Claims.sub(ctx.session.accountId(), ctx.client.sectorIdentifier);
          if (ctx.claims.id_token.sub.value !== subject) {
            return {
              error: 'login_required',
              error_description: 'requested subject could not be obtained',
              reason: 'claims_id_token_sub_value',
              reason_description:
              `${clientName} asks you to Sign-in with a specific identity.`,
            };
          }
        }
        return false;
      },

      // none of multiple authentication context class references requested
      // are met
      () => {
        const request = _.get(ctx.claims, 'id_token.acr', {});
        if (request.essential && request.values) {
          if (request.values.indexOf(ctx.session.acr()) === -1) {
            return {
              error: 'login_required',
              error_description: 'none of the requested ACRs could not be obtained',
              reason: 'essential_acrs',
              reason_description: `${clientName} asks you to Sign-in using a specific method.`,
            };
          }
        }
        return false;
      },

      // single requested authentication context class reference is not met
      () => {
        const request = _.get(ctx.claims, 'id_token.acr', {});
        if (request.essential && request.value) {
          if (request.value !== ctx.session.acr()) {
            return {
              error: 'login_required',
              error_description: 'requested ACR could not be obtained',
              reason: 'essential_acr',
              reason_description: `${clientName} asks you to Sign-in using a specific method.`,
            };
          }
        }
        return false;
      },

      // any unfulfilled prompts other than none or login
      () => {
        const missed = _.find(ctx.prompts, (prompt) => {
          if (prompt !== 'none' && ctx.prompted(prompt)) {
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

      // client not authorized in session yet
      // TODO: strategies
      // - authorize once per session
      // - pass everyone
      // - check account model
      () => {
        if (!ctx.session.sidFor(ctx.client.clientId)) {
          return {
            error: 'consent_required',
            error_description: 'client not authorized for End-User session yet',
            reason: 'client_not_authorized',
          };
        }

        return false;
      },

      () => {
        if (ctx.params.id_token_hint !== undefined) {
          const actualSub = Claims.sub(ctx.session.accountId(), ctx.client.sectorIdentifier);
          const IdToken = provider.IdToken;

          return IdToken.validate(ctx.params.id_token_hint, ctx.client).then((decoded) => {
            if (decoded.payload.sub !== actualSub) {
              return {
                error: 'login_required',
                error_description: 'id_token_hint and authenticated subject do not match',
                reason: 'id_token_hint',
                reason_description: `${clientName} asks that you Sign-in with a specific identity.`,
              };
            }

            return false;
          }, (err) => {
            throw new errors.InvalidRequestError(
              `could not validate id_token_hint (${err.message})`);
          });
        }

        return false;
      },
    ];

    let interaction;

    for (const fn of interactionChecks) { // eslint-disable-line no-restricted-syntax
      interaction = fn();
      if (interaction instanceof Promise) interaction = yield interaction;
      if (interaction) break;
    }

    if (interaction) {
      _.defaults(interaction, {
        error: 'interaction_required',
        error_description: 'interaction is required from the end-user',
      });

      // if interaction needed but prompt=none => throw;
      this.assert(!ctx.prompted('none'), 302, interaction.error, {
        error_description: interaction.error_description,
      });

      const destination = instance(provider).configuration('interactionUrl').call(this, interaction);
      const cookieOptions = instance(provider).configuration('cookies.short');

      this.cookies.set('_grant', j({
        interaction,
        uuid: ctx.uuid,
        returnTo: ctx.urlFor('resume', { grant: ctx.uuid }),
        params: ctx.params,
      }), Object.assign({ path: url.parse(destination).pathname }, cookieOptions));

      this.cookies.set('_grant', j(ctx.params), Object.assign({
        path: provider.pathFor('resume', { grant: ctx.uuid }),
      }, cookieOptions));

      provider.emit('interaction.started', interaction, this);
      return this.redirect(destination);
    }

    return yield next;
  };
};
