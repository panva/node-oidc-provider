import * as crypto from 'node:crypto';

import { InvalidClient, InvalidRequest, OIDCProviderError } from '../helpers/errors.js';
import * as JWT from '../helpers/jwt.js';
import redirectUri from '../helpers/redirect_uri.js';
import instance from '../helpers/weak_cache.js';
import rejectDupes from '../shared/reject_dupes.js';
import bodyParser from '../shared/conditional_body.js';
import paramsMiddleware from '../shared/assemble_params.js';
import sessionMiddleware from '../shared/session.js';
import revoke from '../helpers/revoke.js';
import noCache from '../shared/no_cache.js';
import formPost from '../response_modes/form_post.js';

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');

export const init = [
  noCache,
  sessionMiddleware,
  parseBody,
  paramsMiddleware.bind(undefined, new Set(['id_token_hint', 'post_logout_redirect_uri', 'state', 'ui_locales', 'client_id', 'logout_hint'])),
  rejectDupes.bind(undefined, {}),

  async function endSessionChecks(ctx, next) {
    const { params } = ctx.oidc;

    let client;
    if (params.id_token_hint) {
      try {
        const idTokenHint = JWT.decode(params.id_token_hint);
        ctx.oidc.entity('IdTokenHint', idTokenHint);
      } catch (err) {
        throw new InvalidRequest('could not decode id_token_hint', undefined, err.message);
      }
      const { payload: { aud: clientId } } = ctx.oidc.entities.IdTokenHint;

      if (params.client_id && params.client_id !== clientId) {
        throw new InvalidRequest('client_id does not match the provided id_token_hint');
      }
      client = await ctx.oidc.provider.Client.find(clientId);
      if (!client) {
        throw new InvalidClient('unrecognized id_token_hint audience', 'client not found');
      }
      try {
        await ctx.oidc.provider.IdToken.validate(params.id_token_hint, client);
      } catch (err) {
        if (err instanceof OIDCProviderError) {
          throw err;
        }

        throw new InvalidRequest('could not validate id_token_hint', undefined, err.message);
      }
      ctx.oidc.entity('Client', client);
    } else if (params.client_id) {
      client = await ctx.oidc.provider.Client.find(params.client_id);
      if (!client) {
        throw new InvalidClient('client is invalid', 'client not found');
      }
      ctx.oidc.entity('Client', client);
    }

    if (client && params.post_logout_redirect_uri !== undefined) {
      if (!client.postLogoutRedirectUriAllowed(params.post_logout_redirect_uri)) {
        throw new InvalidRequest('post_logout_redirect_uri not registered');
      }
    } else if (params.post_logout_redirect_uri !== undefined) {
      params.post_logout_redirect_uri = undefined;
    }

    await next();
  },

  async function renderLogout(ctx) {
    // TODO: generic xsrf middleware to remove this
    const secret = crypto.randomBytes(24).toString('hex');

    ctx.oidc.session.state = {
      secret,
      clientId: ctx.oidc.client ? ctx.oidc.client.clientId : undefined,
      state: ctx.oidc.params.state,
      postLogoutRedirectUri: ctx.oidc.params.post_logout_redirect_uri,
    };

    const action = ctx.oidc.urlFor('end_session_confirm');

    if (ctx.oidc.session.accountId) {
      ctx.type = 'html';
      ctx.status = 200;

      const formHtml = `<form id="op.logoutForm" method="post" action="${action}"><input type="hidden" name="xsrf" value="${secret}"/></form>`;
      await instance(ctx.oidc.provider).features.rpInitiatedLogout.logoutSource(ctx, formHtml);
    } else {
      formPost(ctx, action, {
        xsrf: secret,
        logout: 'yes',
      });
    }
  },
];

export const confirm = [
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

  async function endSession(ctx) {
    const { oidc: { session, params } } = ctx;
    const { state } = session;

    const {
      features: { backchannelLogout },
      cookies: { long: opts },
    } = instance(ctx.oidc.provider).configuration;

    if (backchannelLogout.enabled) {
      const clientIds = Object.keys(session.authorizations || {});

      const back = [];

      for (const clientId of clientIds) {
        if (params.logout || clientId === state.clientId) {
          const client = await ctx.oidc.provider.Client.find(clientId);
          if (client) {
            const sid = session.sidFor(client.clientId);
            if (client.backchannelLogoutUri) {
              const { accountId } = session;
              back.push(client.backchannelLogout(accountId, sid)
                .then(() => {
                  ctx.oidc.provider.emit('backchannel.success', ctx, client, accountId, sid);
                }, (err) => {
                  ctx.oidc.provider.emit('backchannel.error', ctx, err, client, accountId, sid);
                }));
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
            // Drop the grants without offline_access
            // Note: tokens that don't get dropped due to offline_access having being added
            // later will still not work, as such they will be orphaned until their TTL hits
            if (grantId && !session.authorizationFor(clientId).persistsLogout) {
              await revoke(ctx, grantId);
            }
          }),
        );
      }

      await session.destroy();

      ctx.cookies.set(
        ctx.oidc.provider.cookieName('session'),
        null,
        opts,
      );
    } else if (state.clientId) {
      const grantId = session.grantIdFor(state.clientId);
      if (grantId && !session.authorizationFor(state.clientId).persistsLogout) {
        await revoke(ctx, grantId);
        ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
      }
      session.state = undefined;
      if (session.authorizations) {
        delete session.authorizations[state.clientId];
      }
      session.resetIdentifier();
    }

    const usePostLogoutUri = state.postLogoutRedirectUri;
    const forwardClientId = !usePostLogoutUri && !params.logout && state.clientId;
    const uri = redirectUri(
      usePostLogoutUri ? state.postLogoutRedirectUri : ctx.oidc.urlFor('end_session_success'),
      {
        ...(usePostLogoutUri && state.state != null
          ? { state: state.state } : undefined), // != intended
        ...(forwardClientId ? { client_id: state.clientId } : undefined),
      },
    );

    ctx.oidc.provider.emit('end_session.success', ctx);

    ctx.status = 303;
    ctx.redirect(uri);
  },
];

export const success = [
  noCache,
  paramsMiddleware.bind(undefined, new Set(['client_id'])),
  async function postLogoutSuccess(ctx) {
    if (ctx.oidc.params.client_id) {
      const client = await ctx.oidc.provider.Client.find(ctx.oidc.params.client_id);
      if (!client) {
        throw new InvalidClient('client is invalid', 'client not found');
      }
      ctx.oidc.entity('Client', client);
    }
    await instance(ctx.oidc.provider).features.rpInitiatedLogout.postLogoutSuccessSource(ctx);
  },
];
