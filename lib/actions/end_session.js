const { omit } = require('lodash');
const crypto = require('crypto');
const compose = require('koa-compose');
const url = require('url');

const { InvalidClientError, InvalidRequestError } = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const redirectUri = require('../helpers/redirect_uri');
const instance = require('../helpers/weak_cache');

const rejectDupes = require('../shared/check_dupes');
const bodyParser = require('../shared/conditional_body');
const paramsMiddleware = require('../shared/get_params');

const parseBody = bodyParser('application/x-www-form-urlencoded');

function frameFor(target) {
  return `<iframe src="${target}"></iframe>`;
}

module.exports = function endSessionAction(provider) {
  const STATES = new RegExp(`${provider.cookieName('state')}\\.[^=]+=`, 'g');
  const { Client } = provider;

  async function loadClient(ctx, clientId) {
    // Validate: client_id param
    const client = await Client.find(clientId);
    if (!client) {
      ctx.throw(new InvalidClientError('unrecognized azp or aud claims'));
    }
    return client;
  }

  const {
    postLogoutRedirectUri,
    logoutSource,
    frontchannelLogoutPendingSource,
    cookies: { long: cookiesConfig },
    features: { backchannelLogout, frontchannelLogout },
  } = instance(provider).configuration();

  return {
    get: compose([
      paramsMiddleware(['id_token_hint', 'post_logout_redirect_uri', 'state', 'ui_locales']),

      rejectDupes,

      async function endSessionChecks(ctx, next) {
        const { params } = ctx.oidc;

        if (params.id_token_hint) {
          let client;

          const clientId = (() => {
            try {
              const { payload: { azp, aud } } = JWT.decode(params.id_token_hint);
              return azp || aud;
            } catch (err) {
              return ctx.throw(new InvalidRequestError(`could not decode id_token_hint (${err.message})`));
            }
          })();

          try {
            client = await loadClient(ctx, clientId);
            await provider.IdToken.validate(params.id_token_hint, client);
          } catch (err) {
            ctx.throw(new InvalidRequestError(`could not validate id_token_hint (${err.message})`));
          }

          if (params.post_logout_redirect_uri) {
            if (!client.postLogoutRedirectUriAllowed(params.post_logout_redirect_uri)) {
              ctx.throw(new InvalidRequestError('post_logout_redirect_uri not registered'));
            }
          }

          ctx.oidc.entity('Client', client);
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
            await postLogoutRedirectUri(ctx),
        };

        ctx.type = 'html';
        ctx.status = 200;

        const formhtml = `<form id="op.logoutForm" method="post" action="${ctx.oidc.urlFor('end_session')}"><input type="hidden" name="xsrf" value="${secret}"/></form>`;
        await logoutSource(ctx, formhtml);

        await next();
      },
    ]),

    post: compose([
      parseBody,

      paramsMiddleware(['xsrf', 'logout']),

      rejectDupes,

      async function checkLogoutToken(ctx, next) {
        if (!ctx.oidc.session.logout) {
          ctx.throw(new InvalidRequestError('could not find logout details'));
        }
        if (ctx.oidc.session.logout.secret !== ctx.oidc.params.xsrf) {
          ctx.throw(new InvalidRequestError('xsrf token invalid'));
        }
        await next();
      },

      async function endSession(ctx, next) {
        const { oidc: { session, params } } = ctx;
        const { logout } = session;

        const opts = omit(cookiesConfig, 'maxAge', 'expires');

        const front = [];

        if (backchannelLogout || frontchannelLogout) {
          const clientIds = Object.keys(session.authorizations || {});

          const back = [];

          for (const clientId of clientIds) { // eslint-disable-line no-restricted-syntax
            if (params.logout || clientId === logout.clientId) {
              const client = await Client.find(clientId); // eslint-disable-line no-await-in-loop
              if (client) {
                const sid = session.sidFor(client.clientId);
                if (client.backchannelLogoutUri) {
                  const accountId = session.accountId();
                  back.push(client.backchannelLogout(accountId, sid)
                    .then(() => {
                      provider.emit('backchannel.success', client, accountId, sid, ctx);
                    }, (err) => {
                      provider.emit('backchannel.error', err, client, accountId, sid, ctx);
                    }));
                }
                if (client.frontchannelLogoutUri) {
                  const target = url.parse(client.frontchannelLogoutUri, true);
                  target.search = null;
                  Object.assign(target.query, {
                    sid,
                    iss: provider.issuer,
                  });
                  front.push(url.format(target));
                }
              }
            }
          }

          await Promise.all(back);
        }

        if (logout.clientId) {
          ctx.oidc.entity('Client', await provider.Client.find(logout.clientId));
        }

        if (params.logout) {
          await session.destroy();
          session.destroyed = true;

          // get all cookies matching _state.[clientId](.sig) and drop them
          const cookies = ctx.get('cookie').match(STATES);
          if (cookies) {
            cookies.forEach((val) => {
              const name = val.slice(0, -1);
              if (!name.endsWith('.sig')) ctx.cookies.set(name, null, opts);
            });
          }

          ctx.cookies.set(provider.cookieName('session'), null, opts);
        } else if (logout.clientId) {
          delete session.logout;
          delete session.authorizations[logout.clientId];
          ctx.cookies.set(`${provider.cookieName('state')}.${logout.clientId}`, null, opts);
        }

        const uri = redirectUri(
          logout.postLogoutRedirectUri,
          logout.state != null ? { state: logout.state } : undefined, // != intended
        );

        provider.emit('end_session.success', ctx);

        if (front.length) {
          const frames = front.map(frameFor);
          await frontchannelLogoutPendingSource(ctx, frames, uri, provider.httpOptions().timeout);
        } else {
          ctx.redirect(uri);
        }

        await next();
      },
    ]),
  };
};
