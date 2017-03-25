'use strict';

const _ = require('lodash');
const crypto = require('crypto');
const compose = require('koa-compose');

const errors = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const redirectUri = require('../helpers/redirect_uri');
const instance = require('../helpers/weak_cache');

const rejectDupes = require('../shared/check_dupes');
const bodyParser = require('../shared/conditional_body');
const paramsMiddleware = require('../shared/get_params');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function endSessionAction(provider) {
  const STATES = new RegExp(`${provider.cookieName('state')}\\.(\\S+)=`, 'g');

  async function loadClient(ctx, clientId) {
    // Validate: client_id param
    const client = await provider.Client.find(clientId);
    ctx.assert(client, new errors.InvalidClientError('unrecognized azp or aud claims'));
    return client;
  }

  return {
    get: compose([
      paramsMiddleware(['id_token_hint', 'post_logout_redirect_uri', 'state']),

      rejectDupes,

      async function endSessionChecks(ctx, next) {
        const params = ctx.oidc.params;

        if (params.id_token_hint) {
          let client;

          const clientId = (() => {
            try {
              const jot = JWT.decode(params.id_token_hint);
              return jot.payload.azp || jot.payload.aud;
            } catch (err) {
              return ctx.throw(new errors.InvalidRequestError(
                `could not decode id_token_hint (${err.message})`));
            }
          })();

          try {
            client = await loadClient(ctx, clientId);
            await provider.IdToken.validate(params.id_token_hint, client);
          } catch (err) {
            ctx.throw(new errors.InvalidRequestError(
              `could not validate id_token_hint (${err.message})`));
          }

          if (params.post_logout_redirect_uri) {
            ctx.assert(client.postLogoutRedirectUriAllowed(params.post_logout_redirect_uri),
              new errors.InvalidRequestError('post_logout_redirect_uri not registered'));
          }

          ctx.oidc.client = client;
        } else {
          params.post_logout_redirect_uri = undefined;
        }

        await next();
      },

      async function renderLogout(ctx, next) {
        const secret = crypto.randomBytes(24).toString('hex');

        ctx.oidc.session.logout = {
          secret,
          clientId: ctx.oidc.client ? ctx.oidc.client.clientId : undefined,
          state: ctx.oidc.params.state,
          postLogoutRedirectUri: ctx.oidc.params.post_logout_redirect_uri ||
            instance(provider).configuration('postLogoutRedirectUri'),
        };

        ctx.type = 'html';
        ctx.status = 200;

        const formhtml = `<form id="op.logoutForm" method="post" action="${ctx.oidc.urlFor('end_session')}"><input type="hidden" name="xsrf" value="${secret}"/></form>`;
        await instance(provider).configuration('logoutSource')(ctx, formhtml);

        await next();
      },
    ]),

    post: compose([
      parseBody,

      paramsMiddleware(['xsrf', 'logout']),

      rejectDupes,

      async function checkLogoutToken(ctx, next) {
        ctx.assert(ctx.oidc.session.logout, new errors.InvalidRequestError(
          'could not find logout details'));
        ctx.assert(ctx.oidc.session.logout.secret === ctx.oidc.params.xsrf,
          new errors.InvalidRequestError('xsrf token invalid'));
        await next();
      },

      async function endSession(ctx, next) {
        const params = ctx.oidc.session.logout;

        const opts = _.omit(instance(provider).configuration('cookies.long'), 'maxAge', 'expires');

        if (ctx.oidc.params.logout) {
          if (instance(provider).configuration('features.backchannelLogout')) {
            const Client = provider.Client;
            const clientIds = Object.keys(ctx.oidc.session.authorizations);
            const logouts = clientIds.map(visitedClientId => Client.find(visitedClientId)
              .then((visitedClient) => {
                if (visitedClient && visitedClient.backchannelLogoutUri) {
                  return visitedClient.backchannelLogout(ctx.oidc.session.accountId(),
                    ctx.oidc.session.sidFor(visitedClient.clientId));
                }
                return undefined;
              }));

            await Promise.all(logouts).catch(() => {});
          }

          await ctx.oidc.session.destroy();
          ctx.oidc.session.destroyed = true;

          // get all cookies matching _state.[clientId](.sig) and drop them
          const cookies = ctx.get('cookie').match(STATES);
          if (cookies) {
            cookies.forEach((val) => {
              const name = val.slice(0, -1);
              if (!name.endsWith('.sig')) ctx.cookies.set(val.slice(0, -1), null, opts);
            });
          }

          ctx.cookies.set(provider.cookieName('session'), null, opts);
        } else if (params.clientId) {
          delete ctx.oidc.session.logout;
          delete ctx.oidc.session.authorizations[params.clientId];
          ctx.cookies.set(`${provider.cookieName('state')}.${params.clientId}`, null, opts);
        }

        const uri = redirectUri(params.postLogoutRedirectUri,
          params.state != null ? { state: params.state } : undefined); // eslint-disable-line eqeqeq

        provider.emit('end_session.success', ctx);
        ctx.redirect(uri);

        await next();
      },
    ]),
  };
};
