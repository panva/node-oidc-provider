const querystring = require('querystring');
const { inspect } = require('util');

const _ = require('lodash');
const bodyParser = require('koa-body');
const Router = require('koa-router');

const { renderError } = require('../../lib/helpers/defaults'); // make your own, you'll need it anyway
const Account = require('../support/account');

const keys = new Set();
const debug = obj => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  if (_.isEmpty(value)) return acc;
  acc[key] = inspect(value, { depth: null });
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${value}</strong>` : value; },
});

module.exports = (provider) => {
  const router = new Router();
  const { constructor: { errors: { SessionNotFound } } } = provider;

  router.use(async (ctx, next) => {
    ctx.set('Pragma', 'no-cache');
    ctx.set('Cache-Control', 'no-cache, no-store');
    try {
      await next();
    } catch (err) {
      if (err instanceof SessionNotFound) {
        ctx.status = err.status;
        const { message: error, error_description } = err; // eslint-disable-line camelcase
        renderError(ctx, { error, error_description }, err);
      } else {
        throw err;
      }
    }
  });

  router.get('/interaction/:uid', async (ctx, next) => {
    const {
      uid, prompt, params, session,
    } = await provider.interactionDetails(ctx.req);
    const client = await provider.Client.find(params.client_id);
    if (prompt.name === 'login') {
      await ctx.render('login', {
        client,
        uid,
        details: prompt.details,
        params,
        title: 'Sign-in',
        session: session ? debug(session) : undefined,
        dbg: {
          params: debug(params),
          prompt: debug(prompt),
        },
      });
    } else {
      await ctx.render('interaction', {
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

    await next();
  });

  const body = bodyParser({
    text: false,
    json: false,
  });

  router.post('/interaction/:uid/login', body, async (ctx) => {
    const account = await Account.findByLogin(ctx.request.body.login);

    const result = {
      login: {
        account: account.accountId,
        acr: 'urn:mace:incommon:iap:bronze',
        amr: ['pwd'],
        ts: Math.floor(Date.now() / 1000),
      },
    };

    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: false,
    });
  });

  router.post('/interaction/:uid/confirm', body, async (ctx) => {
    const result = { consent: {} };
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
