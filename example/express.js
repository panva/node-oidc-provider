/* eslint-disable no-console */

import * as path from 'node:path';
import * as url from 'node:url';
import https from 'node:https';
import fs from 'node:fs';

import { dirname } from 'desm';
import express from 'express'; // eslint-disable-line import/no-unresolved
import helmet from 'helmet';

import Provider from '../lib/index.js'; // from 'oidc-provider';

import Account from './support/account.js';
import configuration from './support/configuration.js';
import routes from './routes/express.js';

const __dirname = dirname(import.meta.url);

const { PORT = 3000, ISSUER = `https://localhost:${PORT}` } = process.env;
configuration.findAccount = Account.findAccount;

const app = express();

const directives = helmet.contentSecurityPolicy.getDefaultDirectives();
delete directives['form-action'];
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives,
  },
}));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

let server;
try {
  let adapter;
  if (process.env.MONGODB_URI) {
    ({ default: adapter } = await import('./adapters/mongodb.js'));
    await adapter.connect();
  }

  const prod = process.env.NODE_ENV === 'production';

  const provider = new Provider(ISSUER, { adapter, ...configuration });

  if (prod) {
    app.enable('trust proxy');
    provider.proxy = true;

    app.use((req, res, next) => {
      if (req.secure) {
        next();
      } else if (req.method === 'GET' || req.method === 'HEAD') {
        res.redirect(url.format({
          protocol: 'https',
          host: req.get('host'),
          pathname: req.originalUrl,
        }));
      } else {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'do yourself a favor and only use https',
        });
      }
    });
  } else {
    const { invalidate: orig } = provider.Client.Schema.prototype;

    provider.Client.Schema.prototype.invalidate = function invalidate(message, code) {
      if (code === 'implicit-force-https' || code === 'implicit-forbid-localhost') {
        return;
      }

      orig.call(this, message);
    };
  }

  routes(app, provider);
  app.use(provider.callback());
  // server = app.listen(PORT, () => {
  //   console.log(`application is listening on port ${PORT}, check its /.well-known/openid-configuration`);
  // });
  const options = {
    key: fs.readFileSync('localhost-key.pem'),
    cert: fs.readFileSync('localhost.pem'),
  };
  server = https.createServer(options, app);
  server.listen(PORT);
} catch (err) {
  if (server?.listening) server.close();
  console.error(err);
  process.exitCode = 1;
}
