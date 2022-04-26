/* eslint-disable no-console, max-len, camelcase, no-unused-vars */
const { strict: assert } = require('assert');
const querystring = require('querystring');
const crypto = require('crypto');
const { inspect } = require('util');

const isEmpty = require('lodash/isEmpty');
const bodyParser = require('koa-body');
const Router = require('koa-router');

const { renderError } = require('../../lib/helpers/defaults')(); // make your own, you'll need it anyway
const Account = require('../support/account');

const keys = new Set();
const debug = (obj) => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  if (isEmpty(value)) return acc;
  acc[key] = inspect(value, { depth: null });
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${value}</strong>` : value; },
});

module.exports = (provider) => {
  const router = new Router();
  const { constructor: { errors: { SessionNotFound } } } = provider;

  router.use(async (ctx, next) => {
    ctx.set('cache-control', 'no-store');
    try {
      await next();
    } catch (err) {
      if (err instanceof SessionNotFound) {
        ctx.status = err.status;
        const { message: error, error_description } = err;
        renderError(ctx, { error, error_description }, err);
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
          google: ctx.google,
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

  router.get('/interaction/callback/google', (ctx) => {
    const nonce = ctx.res.locals.cspNonce;
    return ctx.render('repost', { layout: false, upstream: 'google', nonce });
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

  router.post('/interaction/:uid/federated', body, async (ctx) => {
    const { prompt: { name } } = await provider.interactionDetails(ctx.req, ctx.res);
    assert.equal(name, 'login');

    const path = `/interaction/${ctx.params.uid}/federated`;

    switch (ctx.request.body.upstream) {
      case 'google': {
        const callbackParams = ctx.google.callbackParams(ctx.req);

        // init
        if (!Object.keys(callbackParams).length) {
          const state = `${ctx.params.uid}|${crypto.randomBytes(32).toString('hex')}`;
          const nonce = crypto.randomBytes(32).toString('hex');

          ctx.cookies.set('google.state', state, { path, sameSite: 'strict' });
          ctx.cookies.set('google.nonce', nonce, { path, sameSite: 'strict' });

          ctx.status = 303;
          return ctx.redirect(ctx.google.authorizationUrl({
            state, nonce, scope: 'openid email profile',
          }));
        }

        // callback
        const state = ctx.cookies.get('google.state');
        ctx.cookies.set('google.state', null, { path });
        const nonce = ctx.cookies.get('google.nonce');
        ctx.cookies.set('google.nonce', null, { path });

        const tokenset = await ctx.google.callback(undefined, callbackParams, { state, nonce, response_type: 'id_token' });
        const account = await Account.findByFederated('google', tokenset.claims());

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
  });

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
      // eslint-disable-next-line no-restricted-syntax
      for (const [indicator, scope] of Object.entries(details.missingResourceScopes)) {
        grant.addResourceScope(indicator, scope.join(' '));
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
