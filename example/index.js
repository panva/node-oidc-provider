/* eslint-disable no-console */
'use strict';

const path = require('path');
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
const issuer = process.env.HEROKU ?
  'https://guarded-cliffs-8635.herokuapp.com/op' : 'http://oidc.dev/op';

const provider = new Provider(issuer, {
  config: settings.config,
});

Object.defineProperty(provider, 'Account', {
  value: Account,
});

if (process.env.HEROKU) {
  app.proxy = true;
  provider.configuration.cookies.short.secure = true;
  provider.configuration.cookies.long.secure = true;
}

app.use(rewrite(/^\/\.well-known\/(.*)/, '/op/.well-known/$1'));
app.use(mount('/op', provider.app));

const router = new Router();

router.get('/interaction/:grant', function * renderInteraction(next) {
  const grant = JSON.parse(this.cookies.get('_grant', {
    signed: true,
  })).params;

  const client = provider.Client.find(grant.client_id);

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
    // decline the full profile
    // consent: {
    //   decline: {} || null || "" (_.isEmpty() => true)
    // },
    // decline one from profile.
    // consent: {
    //   decline: {
    //     profile: null
    //   }
    // }
  };

  provider.respond(this, this.request.body.grant, result);
});

app.use(router.routes());
app.use(router.allowedMethods());

Promise.all(settings.certificates.map(cert => provider.addKey(cert)))
  .then(() => Promise.all(
    settings.clients.map(client => provider.Client.add(client))
  ).catch((err) => {
    console.log(err);
  }))
  .then(
    () => app.listen(port));
