'use strict';

let path = require('path');
let koa = require('koa');
let body = require('koa-body');
let port = process.env.PORT || 3000;
let mount = require('koa-mount');
let querystring = require('querystring');
let rewrite = require('koa-rewrite');
let Router = require('koa-router');
let render = require('koa-ejs');

let app = koa();

render(app, {
  cache: false,
  layout: false,
  root: path.join(__dirname, 'views'),
});

app.keys = ['some secret key', 'and also the old one'];

let Account = require('./account');
let settings = require('./settings');

let Provider = require('../lib').Provider;
let issuer = process.env.HEROKU ?
  'https://guarded-cliffs-8635.herokuapp.com/op' : 'http://oidc.dev/op';

let provider = new Provider(issuer, {
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
app.use(mount('/op', provider.application));

let router = new Router();

router.get('/interaction/:grant', function * (next) {

  let grant = JSON.parse(this.cookies.get('_grant', {
    signed: true,
  })).params;

  let client = provider.Client.find(grant.client_id);

  yield this.render('login', {
    action: '/login',
    client: client,
    debug: querystring.stringify(grant, ',<br/>', ' = ', {
      encodeURIComponent: (value) => value,
    }),
    grant: this.params.grant,
    request: grant,
  });

  yield next;
});

router.post('/login', body(), function * () {

  let account = yield Account.findByLogin(this.request.body.login);

  let result = {
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
  .then(() => {
    return Promise.all(
        settings.clients.map(client => provider.Client.add(client))
      ).catch((err) => {
        console.log(err);
      });
  })
  .then(
    () => app.listen(port));
