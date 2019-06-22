/* eslint-disable no-console */

const path = require('path');

const { set } = require('lodash');
const render = require('koa-ejs');
const helmet = require('koa-helmet');

const Provider = require('../lib'); // require('oidc-provider');
const Account = require('../example/support/account');
const routes = require('../example/routes/koa');

const configuration = require('./configuration');

const { GOOGLE_CLIENT_ID, PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;
configuration.findAccount = Account.findAccount;

let server;

(async () => {
  let adapter;
  if (process.env.MONGODB_URI) {
    adapter = require('./heroku_mongo_adapter'); // eslint-disable-line global-require
    await adapter.connect();
  }

  const provider = new Provider(ISSUER, { adapter, ...configuration });

  if (GOOGLE_CLIENT_ID) {
    const openid = require('openid-client'); // eslint-disable-line global-require, import/no-unresolved
    const google = await openid.Issuer.discover('https://accounts.google.com/.well-known/openid-configuration');
    const googleClient = new google.Client({
      client_id: GOOGLE_CLIENT_ID,
      response_types: ['id_token'],
      redirect_uris: [`${ISSUER}/interaction/callback/google`],
      grant_types: ['implicit'],
    });
    provider.app.context.google = googleClient;
  }

  // don't wanna re-bundle the interactions so just insert the login amr and acr as static whenever
  // login is submitted, usually you would submit them from your interaction
  const { interactionFinished } = provider;
  provider.interactionFinished = (...args) => {
    const { login } = args[2];
    if (login) {
      Object.assign(args[2].login, {
        acr: 'urn:mace:incommon:iap:bronze',
        amr: login.account.startsWith('google.') ? ['google'] : ['pwd'],
      });
    }

    return interactionFinished.call(provider, ...args);
  };

  provider.use(helmet());
  provider.use((ctx, next) => {
    if (ctx.path !== '/.well-known/oauth-authorization-server') {
      return next();
    }

    ctx.path = '/.well-known/openid-configuration';
    return next().then(() => {
      ctx.path = '/.well-known/oauth-authorization-server';
    });
  });

  if (process.env.NODE_ENV === 'production') {
    provider.proxy = true;
    set(configuration, 'cookies.short.secure', true);
    set(configuration, 'cookies.long.secure', true);

    provider.use(async (ctx, next) => {
      if (ctx.secure) {
        const orig = ctx.get;

        // this instance uses caddy as a webserver, caddy is escaping the cert values when passing
        // them as headers
        ctx.get = function get(header) {
          const value = orig.call(ctx, header);

          if (header.toLowerCase() === 'x-ssl-client-cert') {
            return unescape(value.replace(/\+/g, ' '));
          }

          return value;
        };

        await next();

        if (ctx.oidc && ctx.oidc.route === 'discovery') {
          ctx.body.mtls_endpoint_aliases = {};
          ['token', 'introspection', 'revocation', 'userinfo', 'device_authorization'].forEach((endpoint) => {
            if (!ctx.body[`${endpoint}_endpoint`]) {
              return;
            }

            ctx.body.mtls_endpoint_aliases[`${endpoint}_endpoint`] = ctx.body[`${endpoint}_endpoint`].replace('https://', 'https://mtls.');
            if (ctx.body[`${endpoint}_endpoint_auth_methods_supported`]) {
              const methods = new Set(ctx.body[`${endpoint}_endpoint_auth_methods_supported`]);
              methods.delete('self_signed_tls_client_auth');
              ctx.body[`${endpoint}_endpoint_auth_methods_supported`] = [...methods];
              ctx.body.mtls_endpoint_aliases[`${endpoint}_endpoint_auth_methods_supported`] = ['self_signed_tls_client_auth'];
            }
          });
        }
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
  render(provider.app, {
    cache: false,
    viewExt: 'ejs',
    layout: '_layout',
    root: path.join(__dirname, '..', 'example', 'views'),
  });
  provider.use(routes(provider).routes());
  server = provider.listen(PORT, () => {
    console.log(`application is listening on port ${PORT}, check its /.well-known/openid-configuration`);
  });
})().catch((err) => {
  if (server && server.listening) server.close();
  console.error(err);
  process.exitCode = 1;
});
