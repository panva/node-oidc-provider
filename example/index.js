/* eslint-disable no-console */
'use strict';

const path = require('path');
const _ = require('lodash');
const koa = require('koa');
const body = require('koa-body');
const port = process.env.PORT || 3000;
const mount = require('koa-mount');
const querystring = require('querystring');
const rewrite = require('koa-rewrite');
const Router = require('koa-router');
const render = require('koa-ejs');

const app = koa();

render(app, {
  cache: false,
  layout: false,
  root: path.join(__dirname, 'views'),
});

app.keys = ['some secret key', 'and also the old one'];

const Account = require('./account');
const settings = require('./settings');

const Provider = require('../lib').Provider;
let issuer = 'http://oidc.dev/op';

if (process.env.HEROKU) {
  issuer = 'https://guarded-cliffs-8635.herokuapp.com/op';
  settings.config.timeouts = {
    request_uri: 15000,
    sector_identifier_uri: 15000,
    jwks_uri: 15000,
  };
  app.proxy = true;
  _.set(settings.config, 'cookies.short.secure', true);
  _.set(settings.config, 'cookies.long.secure', true);
}

const provider = new Provider(issuer, settings.config);

Object.defineProperty(provider, 'Account', {
  value: Account,
});

app.use(rewrite(/^\/\.well-known\/(.*)/, '/op/.well-known/$1'));
app.use(mount('/op', provider.app));

const router = new Router();

router.get('/interaction/:grant', function * renderInteraction(next) {
  const grant = JSON.parse(this.cookies.get('_grant', {
    signed: true,
  })).params;

  const client = yield provider.get('Client').find(grant.client_id);

  yield this.render('login', {
    client,
    action: '/login',
    debug: querystring.stringify(grant, ',<br/>', ' = ', {
      encodeURIComponent: (value) => value,
    }),
    grant: this.params.grant,
    request: grant,
  });

  yield next;
});

router.post('/login', body(), function * submitLoginForm() {
  const account = yield Account.findByLogin(this.request.body.login);

  const result = {
    login: {
      account: account.accountId,
      acr: '1',
      remember: !!this.request.body.remember,
      ts: Date.now() / 1000 | 0,
    },
  };

  provider.resume(this, this.request.body.grant, result);
});

app.use(router.routes());
app.use(router.allowedMethods());

Promise.all(settings.certificates.map(cert => provider.addKey(cert)))
  .then(() => Promise.all(
    settings.clients.map(client => provider.addClient(client))
  ).catch(console.error))
  .then(
    () => app.listen(port));
