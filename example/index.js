'use strict';

/* eslint-disable no-console */

const Provider = require('../lib');
const path = require('path');
const _ = require('lodash');
const bodyParser = require('koa-body');
const querystring = require('querystring');
const Router = require('koa-router');
const render = require('koa-ejs');
const co = require('co');

const port = process.env.PORT || 3000;

const Account = require('./account');
const settings = require('./settings');

const issuer = process.env.ISSUER || 'http://localhost:3000';

if (process.env.MONGODB_URI) {
  const MongoAdapter = require('./adapters/mongodb'); // eslint-disable-line global-require
  settings.config.adapter = MongoAdapter;
}

settings.config.findById = Account.findById;
const clients = settings.clients;

const provider = new Provider(issuer, settings.config);

if (process.env.HEROKU) {
  provider.defaultHttpOptions = { timeout: 15000 };
}

provider.initialize({
  clients,
  keystore: { keys: settings.certificates },
  integrity: { keys: settings.integrityKeys },
}).then(() => {
  render(provider.app, {
    cache: false,
    layout: '_layout',
    root: path.join(__dirname, 'views'),
  });
  provider.app.context.render = co.wrap(provider.app.context.render);

  provider.app.keys = ['some secret key', 'and also the old one'];

  if (process.env.NODE_ENV === 'production') {
    provider.app.proxy = true;
    _.set(settings.config, 'cookies.short.secure', true);
    _.set(settings.config, 'cookies.long.secure', true);

    provider.app.middleware.unshift(async (ctx, next) => {
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

  router.get('/interaction/:grant', async (ctx, next) => {
    const cookie = provider.interactionDetails(ctx.req);
    const client = await provider.Client.find(cookie.params.client_id);

    if (cookie.interaction.error === 'login_required') {
      await ctx.render('login', {
        client,
        cookie,
        title: 'Sign-in',
        debug: querystring.stringify(cookie.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(cookie.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    } else {
      await ctx.render('interaction', {
        client,
        cookie,
        title: 'Authorize',
        debug: querystring.stringify(cookie.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(cookie.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    }

    await next();
  });

  const body = bodyParser();

  router.post('/interaction/:grant/confirm', body, async (ctx, next) => {
    const result = { consent: {} };
    provider.interactionFinished(ctx.req, ctx.res, result);
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

    provider.interactionFinished(ctx.req, ctx.res, result);
    await next();
  });

  provider.app.use(router.routes());
})
.then(() => provider.app.listen(port))
.catch((err) => {
  console.error(err);
  process.exit(1);
});
