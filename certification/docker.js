/* eslint-disable no-console */

const path = require('path');
const https = require('https');

const pem = require('https-pem');
const render = require('koa-ejs');

const { Provider } = require('../lib'); // require('oidc-provider');
const Account = require('../example/support/account');
const routes = require('../example/routes/koa');

const configuration = require('./configuration');

const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;
configuration.findAccount = Account.findAccount;

const provider = new Provider(ISSUER, configuration);

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

render(provider.app, {
  cache: false,
  viewExt: 'ejs',
  layout: '_layout',
  root: path.join(__dirname, '..', 'example', 'views'),
});
provider.use(routes(provider).routes());
const server = https.createServer(pem, provider.callback);
server.listen(PORT);
