/* eslint-disable no-console */

import * as path from 'node:path';
import * as https from 'node:https';

import { generate } from 'selfsigned';
import render from '@koa/ejs';
import { dirname } from 'desm';

import Provider from '../../lib/index.js'; // from 'oidc-provider';
import Account from '../../example/support/account.js';
import routes from '../../example/routes/koa.js';

import configuration from './configuration.js';

const selfsigned = generate();
const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;
configuration.findAccount = Account.findAccount;

const provider = new Provider(ISSUER, configuration);
const __dirname = dirname(import.meta.url);

// don't wanna re-bundle the interactions so just insert the login amr and acr as static whenever
// login is submitted, usually you would submit them from your interaction
const { interactionFinished } = provider;
provider.interactionFinished = (...args) => {
  const { login } = args[2];
  if (login) {
    Object.assign(args[2].login, {
      acr: 'urn:mace:incommon:iap:bronze',
      amr: ['pwd'],
    });
  }

  return interactionFinished.call(provider, ...args);
};

render(provider.app, {
  cache: false,
  viewExt: 'ejs',
  layout: '_layout',
  root: path.join(__dirname, '..', '..', 'example', 'views'),
});
provider.use(routes(provider).routes());
const server = https.createServer({
  key: selfsigned.private,
  cert: selfsigned.cert,
}, provider.callback());
server.listen(PORT, () => {
  console.log(`application is listening on port ${PORT}, check its /.well-known/openid-configuration`);
  process.on('SIGINT', () => {
    process.exit(0);
  });
});
