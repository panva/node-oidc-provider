'use strict';

/* eslint-disable no-console */

const LIB = require('../lib');
const path = require('path');
const _ = require('lodash');
const Koa = require('koa');
const bodyParser = require('koa-body');
const mount = require('koa-mount');
const querystring = require('querystring');
const rewrite = require('koa-rewrite');
const Router = require('koa-router');
const render = require('koa-ejs');
const co = require('co');

const port = process.env.PORT || 3000;
const app = new Koa();

render(app, {
  cache: false,
  layout: '_layout',
  root: path.join(__dirname, 'views'),
});
app.context.render = co.wrap(app.context.render);

app.keys = ['some secret key', 'and also the old one'];

const Account = require('./account');
const settings = require('./settings');

const Provider = LIB.Provider;

const issuer = process.env.ISSUER || 'http://localhost:3000/op';

if (process.env.HEROKU) {
  app.proxy = true;
  _.set(settings.config, 'cookies.short.secure', true);
  _.set(settings.config, 'cookies.long.secure', true);

  app.use(async (ctx, next) => {
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

if (process.env.MONGODB_URI) {
  const MongoAdapter = require('./adapters/mongodb'); // eslint-disable-line global-require

  settings.config.adapter = MongoAdapter;
}

settings.config.findById = Account.findById;

Promise.all([
  LIB.asKeyStore({ keys: settings.certificates }),
  LIB.asKeyStore({ keys: settings.integrityKeys }),
]).then((results) => {
  const keystore = results[0];
  const integrity = results[1];
  const clients = settings.clients;

  const provider = new Provider(issuer, settings.config);

  if (process.env.HEROKU) {
    provider.defaultHttpOptions = { timeout: 15000 };
  }

  return provider.initialize({ keystore, integrity, clients });
}).then((provider) => {
  app.use(rewrite(/^\/\.well-known\/(.*)/, '/op/.well-known/$1'));
  app.use(mount('/op', provider.app));

  const router = new Router();

  router.get('/interaction/:grant', async (ctx, next) => {
    const cookie = JSON.parse(ctx.cookies.get('_grant', { signed: true }));
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

  router.post('/confirm', body, async (ctx, next) => {
    const result = { consent: {} };
    provider.resume(ctx, ctx.request.body.uuid, result);
    await next();
  });

  router.post('/login', body, async (ctx, next) => {
    const account = await Account.findByLogin(ctx.request.body.login);

    const result = {
      login: {
        account: account.accountId,
        acr: '1',
        remember: !!ctx.request.body.remember,
        ts: Math.floor(Date.now() / 1000),
      },
      consent: {},
    };

    provider.resume(ctx, ctx.request.body.uuid, result);
    await next();
  });

  app.use(router.routes());
})
.then(() => app.listen(port))
.catch((err) => {
  console.error(err);
  process.exit(1);
});
