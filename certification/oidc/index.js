/* eslint-disable no-console */

import { promisify } from 'node:util';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import { dirname } from 'desm';
import render from '@koa/ejs';
import helmet from 'helmet';

import Provider from '../../lib/index.js'; // from 'oidc-provider';
import Account from '../../example/support/account.js';
import routes from '../../example/routes/koa.js';

import configuration from './configuration.js';

const __dirname = dirname(import.meta.url);

const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;

let server;

try {
  const provider = new Provider(ISSUER, { ...configuration, findAccount: Account.findAccount });

  // don't wanna re-bundle the interactions so just insert the login amr and acr as static whenever
  // login is submitted, usually you would submit them from your interaction
  const { interactionFinished } = provider;
  provider.interactionFinished = (...args) => {
    const { login } = args[2];
    if (login) {
      Object.assign(args[2].login, {
        acr: 'urn:mace:incommon:iap:bronze',
        amr: login.accountId.startsWith('google.') ? ['google'] : ['pwd'],
      });
    }

    return interactionFinished.call(provider, ...args);
  };

  const directives = helmet.contentSecurityPolicy.getDefaultDirectives();
  delete directives['form-action'];
  directives['script-src'] = ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`];
  const pHelmet = promisify(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives,
    },
  }));

  provider.use(async (ctx, next) => {
    const origSecure = ctx.req.secure;
    ctx.req.secure = ctx.request.secure;
    // eslint-disable-next-line no-unused-expressions
    ctx.res.locals ||= {};
    ctx.res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    await pHelmet(ctx.req, ctx.res);
    ctx.req.secure = origSecure;
    return next();
  });

  if (process.env.NODE_ENV === 'production') {
    provider.proxy = true;

    provider.use(async (ctx, next) => {
      if (ctx.secure) {
        await next();

        switch (ctx.oidc?.route) {
          case 'discovery': {
            ctx.body.mtls_endpoint_aliases = {};
            ['token', 'introspection', 'revocation', 'userinfo', 'device_authorization', 'pushed_authorization_request'].forEach((endpoint) => {
              if (!ctx.body[`${endpoint}_endpoint`]) {
                return;
              }

              ctx.body.mtls_endpoint_aliases[`${endpoint}_endpoint`] = ctx.body[`${endpoint}_endpoint`].replace('https://', 'https://mtls.');
            });
            break;
          }
          case 'device_authorization': {
            if (ctx.status === 200) {
              ctx.body.verification_uri = ctx.body.verification_uri.replace('https://mtls.', 'https://');
              ctx.body.verification_uri_complete = ctx.body.verification_uri_complete.replace('https://mtls.', 'https://');
            }
            break;
          }
          default:
        }
      } else if (ctx.method === 'GET' || ctx.method === 'HEAD') {
        ctx.status = 303;
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

  render(provider, {
    cache: false,
    viewExt: 'ejs',
    layout: '_layout',
    root: path.join(__dirname, '..', '..', 'example', 'views'),
  });
  provider.use(routes(provider).routes());
  server = provider.listen(PORT, () => {
    console.log(`application is listening on port ${PORT}, check its /.well-known/openid-configuration`);
    process.on('SIGINT', () => {
      process.exit(0);
    });
  });
} catch (err) {
  if (server?.listening) server.close();
  console.error(err);
  process.exitCode = 1;
}
