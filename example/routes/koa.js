/* eslint-disable no-console, camelcase, no-unused-vars */
import { strict as assert } from 'node:assert';
import * as querystring from 'node:querystring';
import * as crypto from 'node:crypto';
import { inspect, promisify } from 'node:util';

import * as oidc from 'openid-client';
import isEmpty from 'lodash/isEmpty.js';
import { koaBody as bodyParser } from 'koa-body';
import Router from '@koa/router';

import { defaults } from '../../lib/helpers/defaults.js'; // make your own, you'll need it anyway
import Account from '../support/account.js';
import { errors } from '../../lib/index.js'; // from 'oidc-provider';

const hkdf = promisify(crypto.hkdf);
const keys = new Set();
const debug = (obj) => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  if (isEmpty(value)) return acc;
  acc[key] = inspect(value, { depth: null });
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${value}</strong>` : value; },
});

const { SessionNotFound } = errors;

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;

let google;
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  google = await oidc.discovery(new URL('https://accounts.google.com'), GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
}

export default (provider) => {
  const router = new Router();

  router.use(async (ctx, next) => {
    ctx.set('cache-control', 'no-store');
    try {
      await next();
    } catch (err) {
      if (err instanceof SessionNotFound) {
        ctx.status = err.status;
        const { message: error, error_description } = err;
        await defaults.renderError(ctx, { error, error_description }, err);
      } else {
        throw err;
      }
    }
  });

  router.get('/interaction/:uid', async (ctx, next) => {
    const {
      uid, prompt, params, session,
    } = await provider.interactionDetails(ctx.req, ctx.res);
    const client = await provider.Client.find(params.client_id);

    switch (prompt.name) {
      case 'login': {
        return ctx.render('login', {
          client,
          uid,
          details: prompt.details,
          params,
          title: 'Sign-in',
          google,
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt),
          },
        });
      }
      case 'consent': {
        return ctx.render('interaction', {
          client,
          uid,
          details: prompt.details,
          params,
          title: 'Authorize',
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt),
          },
        });
      }
      default:
        return next();
    }
  });

  const body = bodyParser({
    text: false, json: false, patchNode: true, patchKoa: true,
  });

  router.post('/interaction/:uid/login', body, async (ctx) => {
    const { prompt: { name } } = await provider.interactionDetails(ctx.req, ctx.res);
    assert.equal(name, 'login');

    const account = await Account.findByLogin(ctx.request.body.login);

    const result = {
      login: {
        accountId: account.accountId,
      },
    };

    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: false,
    });
  });

  const ENABLE_FEDERATED_ROUTES = process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;
  if (ENABLE_FEDERATED_ROUTES) {
    const GOOGLE_CALLBACK_PATHNAME = '/interaction/callback/google';
    const federatedLogin = async (ctx) => {
      const { prompt: { name } } = await provider.interactionDetails(ctx.req, ctx.res);
      assert.equal(name, 'login');

      switch (ctx.method === 'POST' ? ctx.request.body.upstream : ctx.query.upstream) {
        case 'google': {
          const code_verifier = Buffer.from(
            await hkdf(
              'sha256',
              process.env.GOOGLE_CLIENT_SECRET,
              ctx.params.uid,
              process.env.GOOGLE_CLIENT_ID,
              32,
            ),
          ).toString('base64url');

          if (ctx.method === 'POST') {
            ctx.status = 303;
            return ctx.redirect(oidc.buildAuthorizationUrl(google, {
              redirect_uri: new URL(GOOGLE_CALLBACK_PATHNAME, ctx.request.URL.origin),
              scope: 'openid email profile',
              code_challenge: await oidc.calculatePKCECodeChallenge(code_verifier),
              code_challenge_method: 'S256',
              state: ctx.params.uid,
            }));
          }

          const url = new URL(ctx.request.URL);
          url.pathname = GOOGLE_CALLBACK_PATHNAME;
          const tokens = await oidc.authorizationCodeGrant(google, url, {
            pkceCodeVerifier: code_verifier,
            idTokenExpected: true,
            expectedState: ctx.params.uid,
          });

          const account = await Account.findByFederated('google', tokens.claims());

          const result = {
            login: {
              accountId: account.accountId,
            },
          };
          return provider.interactionFinished(ctx.req, ctx.res, result, {
            mergeWithLastSubmission: false,
          });
        }
        default:
          return undefined;
      }
    };

    router.get(GOOGLE_CALLBACK_PATHNAME, (ctx) => {
      const target = new URL(ctx.request.URL);
      target.pathname = `/interaction/${ctx.query.state}/federated`;
      target.searchParams.set('upstream', 'google');
      ctx.redirect(target);
    });
    router.get('/interaction/:uid/federated', body, federatedLogin);
    router.post('/interaction/:uid/federated', body, federatedLogin);
  }

  router.post('/interaction/:uid/confirm', body, async (ctx) => {
    const interactionDetails = await provider.interactionDetails(ctx.req, ctx.res);
    const { prompt: { name, details }, params, session: { accountId } } = interactionDetails;
    assert.equal(name, 'consent');

    let { grantId } = interactionDetails;
    let grant;

    if (grantId) {
      // we'll be modifying existing grant in existing session
      grant = await provider.Grant.find(grantId);
    } else {
      // we're establishing a new grant
      grant = new provider.Grant({
        accountId,
        clientId: params.client_id,
      });
    }

    if (details.missingOIDCScope) {
      grant.addOIDCScope(details.missingOIDCScope.join(' '));
    }
    if (details.missingOIDCClaims) {
      grant.addOIDCClaims(details.missingOIDCClaims);
    }
    if (details.missingResourceScopes) {
      for (const [indicator, scope] of Object.entries(details.missingResourceScopes)) {
        grant.addResourceScope(indicator, scope.join(' '));
      }
    }
    if (details.rar) {
      for (const rar of details.rar) {
        grant.addRar(rar);
      }
    }

    grantId = await grant.save();

    const consent = {};
    if (!interactionDetails.grantId) {
      // we don't have to pass grantId to consent, we're just modifying existing one
      consent.grantId = grantId;
    }

    const result = { consent };
    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: true,
    });
  });

  router.get('/interaction/:uid/abort', async (ctx) => {
    const result = {
      error: 'access_denied',
      error_description: 'End-User aborted interaction',
    };

    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: false,
    });
  });

  return router;
};
