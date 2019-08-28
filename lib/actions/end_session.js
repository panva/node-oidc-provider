const crypto = require('crypto');
const url = require('url');

const omit = require('lodash/omit');

const { InvalidClient, InvalidRequest, OIDCProviderError } = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const redirectUri = require('../helpers/redirect_uri');
const instance = require('../helpers/weak_cache');
const rejectDupes = require('../shared/reject_dupes');
const bodyParser = require('../shared/conditional_body');
const paramsMiddleware = require('../shared/assemble_params');
const sessionMiddleware = require('../shared/session');
const revokeGrant = require('../helpers/revoke_grant');
const noCache = require('../shared/no_cache');

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');

function frameFor(target) {
  return `<iframe src="${target}"></iframe>`;
}

module.exports = {
  init: [
    noCache,
    sessionMiddleware,
    parseBody,
    paramsMiddleware.bind(undefined, new Set(['id_token_hint', 'post_logout_redirect_uri', 'state', 'ui_locales'])),
    rejectDupes.bind(undefined, {}),

    async function endSessionChecks(ctx, next) {
      const { params } = ctx.oidc;

      if (params.id_token_hint) {
        try {
          const idTokenHint = JWT.decode(params.id_token_hint);
          ctx.oidc.entity('IdTokenHint', idTokenHint);
        } catch (err) {
          throw new InvalidRequest(`could not decode id_token_hint (${err.message})`);
        }
        const { payload: { aud: clientId } } = ctx.oidc.entities.IdTokenHint;

        const client = await ctx.oidc.provider.Client.find(clientId);
        if (!client) {
          throw new InvalidClient('unrecognized id_token_hint audience');
        }
        try {
          await ctx.oidc.provider.IdToken.validate(params.id_token_hint, client);
        } catch (err) {
          if (err instanceof OIDCProviderError) {
            throw err;
          }

          throw new InvalidRequest(`could not validate id_token_hint (${err.message})`);
        }

        if (params.post_logout_redirect_uri) {
          if (!client.postLogoutRedirectUriAllowed(params.post_logout_redirect_uri)) {
            throw new InvalidRequest('post_logout_redirect_uri not registered');
          }
        }

        ctx.oidc.entity('Client', client);
      } else if (params.post_logout_redirect_uri !== undefined) {
        throw new InvalidRequest('post_logout_redirect_uri can only be used in combination with id_token_hint');
      }

      await next();
    },

    async function renderLogout(ctx, next) {
      // TODO: generic xsrf middleware to remove this
      const secret = crypto.randomBytes(24).toString('hex');

      ctx.oidc.session.state = {
        secret,
        clientId: ctx.oidc.client ? ctx.oidc.client.clientId : undefined,
        state: ctx.oidc.params.state,
        postLogoutRedirectUri: ctx.oidc.params.post_logout_redirect_uri || ctx.oidc.urlFor('end_session_success'),
      };

      ctx.type = 'html';
      ctx.status = 200;

      const formHtml = `<form id="op.logoutForm" method="post" action="${ctx.oidc.urlFor('end_session_confirm')}"><input type="hidden" name="xsrf" value="${secret}"/></form>`;
      await instance(ctx.oidc.provider).configuration('logoutSource')(ctx, formHtml);

      await next();
    },
  ],

  confirm: [
    noCache,
    sessionMiddleware,
    parseBody,
    paramsMiddleware.bind(undefined, new Set(['xsrf', 'logout'])),
    rejectDupes.bind(undefined, {}),

    async function checkLogoutToken(ctx, next) {
      if (!ctx.oidc.session.state) {
        throw new InvalidRequest('could not find logout details');
      }
      if (ctx.oidc.session.state.secret !== ctx.oidc.params.xsrf) {
        throw new InvalidRequest('xsrf token invalid');
      }
      await next();
    },

    async function endSession(ctx, next) {
      const { oidc: { session, params } } = ctx;
      const { state } = session;

      const {
        features: { backchannelLogout, frontchannelLogout, sessionManagement },
        cookies: { long: cookiesConfig },
      } = instance(ctx.oidc.provider).configuration();

      const opts = omit(cookiesConfig, 'maxAge', 'expires');

      const front = [];

      if (backchannelLogout.enabled || frontchannelLogout.enabled) {
        const clientIds = Object.keys(session.authorizations || {});

        const back = [];

        for (const clientId of clientIds) { // eslint-disable-line no-restricted-syntax
          if (params.logout || clientId === state.clientId) {
            const client = await ctx.oidc.provider.Client.find(clientId); // eslint-disable-line no-await-in-loop, max-len
            if (client) {
              const sid = session.sidFor(client.clientId);
              if (client.backchannelLogoutUri) {
                const accountId = session.accountId();
                back.push(client.backchannelLogout(accountId, sid)
                  .then(() => {
                    ctx.oidc.provider.emit('backchannel.success', ctx, client, accountId, sid);
                  }, (err) => {
                    ctx.oidc.provider.emit('backchannel.error', ctx, err, client, accountId, sid);
                  }));
              }
              if (client.frontchannelLogoutUri) {
                const target = url.parse(client.frontchannelLogoutUri, true);
                target.search = null;
                if (client.frontchannelLogoutSessionRequired) {
                  Object.assign(target.query, {
                    sid,
                    iss: ctx.oidc.issuer,
                  });
                }
                front.push(url.format(target));
              }
            }
          }
        }

        await Promise.all(back);
      }

      if (state.clientId) {
        ctx.oidc.entity('Client', await ctx.oidc.provider.Client.find(state.clientId));
      }

      if (params.logout) {
        if (session.authorizations) {
          await Promise.all(
            Object.entries(session.authorizations).map(async ([clientId, { grantId }]) => {
              // 1) drop the grants for the client that requested a logout
              // 2) drop the grants without offline_access
              // Note: tokens that don't get dropped due to offline_access having being added
              // later will still not work, as such they will be orphaned until their TTL hits
              if (
                clientId === state.clientId
                || !session.authorizationFor(clientId).persistsLogout
              ) {
                const client = await ctx.oidc.provider.Client.find(clientId).catch(() => {});
                await revokeGrant(ctx.oidc.provider, client, grantId);
                ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
              }
            }),
          );
        }

        await session.destroy();

        if (sessionManagement.enabled) {
          // get all cookies matching _state.[clientId](.sig) and drop them
          const STATES = new RegExp(`${ctx.oidc.provider.cookieName('state')}\\.[^=]+=`, 'g');
          const cookies = ctx.get('cookie').match(STATES);
          if (cookies) {
            cookies.forEach((val) => {
              const name = val.slice(0, -1);
              if (!name.endsWith('.sig')) ctx.oidc.cookies.set(name, null, opts);
            });
          }
        }

        ctx.oidc.cookies.set(ctx.oidc.provider.cookieName('session'), null, opts);
      } else if (state.clientId) {
        const grantId = session.grantIdFor(state.clientId);
        if (grantId) {
          const client = await ctx.oidc.provider.Client.find(state.clientId).catch(() => {});
          await revokeGrant(ctx.oidc.provider, client, grantId);
          ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
        }
        session.state = undefined;
        if (session.authorizations) {
          delete session.authorizations[state.clientId];
        }
        if (sessionManagement.enabled) {
          ctx.oidc.cookies.set(`${ctx.oidc.provider.cookieName('state')}.${state.clientId}`, null, opts);
        }
        session.resetIdentifier();
      }

      const uri = redirectUri(
        state.postLogoutRedirectUri,
        {
          ...(state.state != null ? { state: state.state } : undefined), // != intended
          ...(!params.logout && state.clientId ? { client_id: state.clientId } : undefined),
        },
      );

      ctx.oidc.provider.emit('end_session.success', ctx);

      if (front.length) {
        const frames = front.map(frameFor);
        await frontchannelLogout.logoutPendingSource(ctx, frames, uri);
      } else {
        ctx.redirect(uri);
      }

      await next();
    },
  ],

  success: [
    noCache,
    paramsMiddleware.bind(undefined, new Set(['client_id'])),
    async function postLogoutSuccess(ctx) {
      if (ctx.oidc.params.client_id) {
        const client = await ctx.oidc.provider.Client.find(ctx.oidc.params.client_id);
        if (!client) {
          throw new InvalidClient();
        }
        ctx.oidc.entity('Client', client);
      }
      await instance(ctx.oidc.provider).configuration('postLogoutSuccessSource')(ctx);
    },
  ],
};
