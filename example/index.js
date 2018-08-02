/* eslint-disable no-console */

const path = require('path');
const querystring = require('querystring');

const { set } = require('lodash');
const bodyParser = require('koa-body');
const Router = require('koa-router');
const render = require('koa-ejs');
const helmet = require('koa-helmet');

const Provider = require('../lib');
const { renderError } = require('../lib/helpers/defaults'); // make your own, you'll need it anyway

const port = process.env.PORT || 3000;

const Account = require('./account');
const { config, clients, certificates } = require('./settings');

const issuer = process.env.ISSUER || 'http://localhost:3000';

config.findById = Account.findById;

const provider = new Provider(issuer, config);
const { errors: { SessionNotFound } } = Provider;

provider.defaultHttpOptions = { timeout: 15000 };
provider.use(helmet());

provider.initialize({
  adapter: process.env.MONGODB_URI ? require('./heroku_mongo_adapter') : undefined, // eslint-disable-line global-require
  clients,
  keystore: { keys: certificates },
}).then(() => {
  render(provider.app, {
    cache: false,
    layout: '_layout',
    root: path.join(__dirname, 'views'),
  });

  if (process.env.NODE_ENV === 'production') {
    provider.proxy = true;
    set(config, 'cookies.short.secure', true);
    set(config, 'cookies.long.secure', true);

    provider.use(async (ctx, next) => {
      if (ctx.secure) {
        await next();
      } else if (ctx.method === 'GET' || ctx.method === 'HEAD') {
        ctx.redirect(ctx.href.replace(/^http:\/\//i, 'https://'));
      } else {
        ctx.body = {
          error: 'invalid_request',
          error_description: 'do yourself a favor and only use https',
        };
        ctx.status = 400;
      }
    });
  }

  const router = new Router();

  router.use(async (ctx, next) => {
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
        debug: querystring.stringify(details.params, ',<br/>', ' = ', {
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
        debug: querystring.stringify(details.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(details.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    }

    await next();
  });

  const body = bodyParser();

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

  provider.use(router.routes());
})
  .then(() => provider.listen(port))
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
