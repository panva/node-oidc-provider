/* eslint-disable no-console */

const path = require('path');

const { set } = require('lodash');
const Koa = require('koa');
const render = require('koa-ejs');
const helmet = require('koa-helmet');
const mount = require('koa-mount');

const Provider = require('../lib'); // require('oidc-provider');

const Account = require('./support/account');
const { provider: providerConfiguration, clients, keys } = require('./support/configuration');
const routes = require('./routes/koa');

const { PORT = 3000, ISSUER = `http://localhost:${PORT}`, TIMEOUT } = process.env;
providerConfiguration.findById = Account.findById;

const app = new Koa();
app.use(helmet());
render(app, {
  cache: false,
  viewExt: 'ejs',
  layout: '_layout',
  root: path.join(__dirname, 'views'),
});

if (process.env.NODE_ENV === 'production') {
  app.keys = providerConfiguration.cookies.keys;
  app.proxy = true;
  set(providerConfiguration, 'cookies.short.secure', true);
  set(providerConfiguration, 'cookies.long.secure', true);

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

const provider = new Provider(ISSUER, providerConfiguration);
if (TIMEOUT) {
  provider.defaultHttpOptions = { timeout: parseInt(TIMEOUT, 10) };
}

let server;
(async () => {
  await provider.initialize({
    adapter: process.env.MONGODB_URI ? require('./support/heroku_mongo_adapter') : undefined, // eslint-disable-line global-require
    clients,
    keystore: { keys },
  });
  app.use(routes(provider).routes());
  app.use(mount(provider.app));
  server = app.listen(PORT, () => {
    console.log(`application is listening on port ${PORT}, check it's /.well-known/openid-configuration`);
  });
})().catch((err) => {
  if (server && server.listening) server.close();
  console.error(err);
  process.exitCode = 1;
});
