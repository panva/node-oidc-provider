const querystring = require('querystring');

const bodyParser = require('koa-body');
const Router = require('koa-trie-router');

const { renderError } = require('../../lib/helpers/defaults'); // make your own, you'll need it anyway
const Account = require('../support/account');

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

  router.get('/interaction/:grant', async (ctx, next) => {
    const details = await provider.interactionDetails(ctx.req);
    const client = await provider.Client.find(details.params.client_id);

    if (details.interaction.error === 'login_required') {
      await ctx.render('login', {
        client,
        details,
        title: 'Sign-in',
        params: querystring.stringify(details.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(details.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    } else {
      await ctx.render('interaction', {
        client,
        details,
        title: 'Authorize',
        params: querystring.stringify(details.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(details.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    }

    await next();
  });

  const body = bodyParser({
    text: false,
    json: false,
  });

  router.post('/interaction/:grant/confirm', body, async (ctx, next) => {
    const result = { consent: {} };
    await provider.interactionFinished(ctx.req, ctx.res, result);
    await next();
  });

  router.post('/interaction/:grant/login', body, async (ctx, next) => {
    const account = await Account.findByLogin(ctx.request.body.login);

    const result = {
      login: {
        account: account.accountId,
        acr: 'urn:mace:incommon:iap:bronze',
        amr: ['pwd'],
        remember: !!ctx.request.body.remember,
        ts: Math.floor(Date.now() / 1000),
      },
      consent: {},
    };

    await provider.interactionFinished(ctx.req, ctx.res, result);
    await next();
  });

  return router;
};
