/* eslint-disable no-console */

const path = require('path');

const set = require('lodash/set');
const Koa = require('koa');
const render = require('koa-ejs');
const helmet = require('koa-helmet');
const mount = require('koa-mount');

const { Provider } = require('../lib'); // require('oidc-provider');

const Account = require('./support/account');
const configuration = require('./support/configuration');
const routes = require('./routes/koa');

const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;
configuration.findAccount = Account.findAccount;

const app = new Koa();
app.use(helmet());
render(app, {
  cache: false,
  viewExt: 'ejs',
  layout: '_layout',
  root: path.join(__dirname, 'views'),
});

if (process.env.NODE_ENV === 'production') {
  app.proxy = true;
  set(configuration, 'cookies.short.secure', true);
  set(configuration, 'cookies.long.secure', true);

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

let server;
(async () => {
  let adapter;
  if (process.env.MONGODB_URI) {
    adapter = require('./adapters/mongodb'); // eslint-disable-line global-require
    await adapter.connect();
  }

  const provider = new Provider(ISSUER, { adapter, ...configuration });

  provider.use(helmet());

  app.use(routes(provider).routes());
  app.use(mount(provider.app));
  server = app.listen(PORT, () => {
    console.log(`application is listening on port ${PORT}, check its /.well-known/openid-configuration`);
  });
})().catch((err) => {
  if (server && server.listening) server.close();
  console.error(err);
  process.exitCode = 1;
});
