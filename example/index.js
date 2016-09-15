/* eslint-disable no-console */
'use strict';

const LIB = require('../lib');
const path = require('path');
const _ = require('lodash');
const koa = require('koa');
const bodyParser = require('koa-body');
const mount = require('koa-mount');
const querystring = require('querystring');
const rewrite = require('koa-rewrite');
const Router = require('koa-router');
const render = require('koa-ejs');

const port = process.env.PORT || 3000;
const app = koa();

render(app, {
  cache: false,
  layout: '_layout',
  root: path.join(__dirname, 'views'),
});

app.keys = ['some secret key', 'and also the old one'];

const Account = require('./account');
const settings = require('./settings');

const Provider = LIB.Provider;

const issuer = process.env.ISSUER || 'http://localhost:3000/op';

if (process.env.HEROKU) {
  app.proxy = true;
  _.set(settings.config, 'cookies.short.secure', true);
  _.set(settings.config, 'cookies.long.secure', true);

  app.use(function* ensureSecure(next) {
    if (this.secure) {
      yield next;
    } else if (this.method === 'GET' || this.method === 'HEAD') {
      this.redirect(this.href.replace(/^http:\/\//i, 'https://'));
    } else {
      this.body = {
        error: 'invalid_request',
        error_description: 'do yourself a favor and only use https',
      };
      this.status = 400;
    }
  });
}

if (process.env.MONGODB_URI) {
  const MongoAdapter = require('./adapters/mongodb'); // eslint-disable-line global-require

  settings.config.adapter = MongoAdapter;
}

settings.config.findById = Account.findById;

Promise.all([
  LIB.asKeyStore({ keys: settings.certificates }),
  LIB.asKeyStore({ keys: settings.integrityKeys }),
]).then((results) => {
  const keystore = results[0];
  const tokenIntegrity = results[1];

  settings.config.keystore = keystore;
  settings.config.tokenIntegrity = tokenIntegrity;

  const provider = new Provider(issuer, settings.config);

  if (process.env.HEROKU) {
    provider.defaultHttpOptions = { timeout: 15000 };
  }

  app.use(rewrite(/^\/\.well-known\/(.*)/, '/op/.well-known/$1'));
  app.use(mount('/op', provider.app));

  const router = new Router();

  router.get('/interaction/:grant', function* renderInteraction(next) {
    const cookie = JSON.parse(this.cookies.get('_grant', { signed: true }));
    const client = yield provider.Client.find(cookie.params.client_id);

    if (cookie.interaction.error === 'login_required') {
      yield this.render('login', {
        client,
        cookie,
        title: 'Sign-in',
        debug: querystring.stringify(cookie.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(cookie.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    } else {
      yield this.render('interaction', {
        client,
        cookie,
        title: 'Authorize',
        debug: querystring.stringify(cookie.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(cookie.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    }


    yield next;
  });

  const body = bodyParser();

  router.post('/confirm', body, function* submitConfirmationForm(next) {
    const result = { consent: {} };
    provider.resume(this, this.request.body.uuid, result);
    yield next;
  });

  router.post('/login', body, function* submitLoginForm() {
    const account = yield Account.findByLogin(this.request.body.login);

    const result = {
      login: {
        account: account.accountId,
        acr: '1',
        remember: !!this.request.body.remember,
        ts: Math.floor(Date.now() / 1000),
      },
      consent: {},
    };

    provider.resume(this, this.request.body.uuid, result);
  });

  app.use(router.routes());

  return Promise.all(settings.clients.map(client => provider.addClient(client)));
})
.then(() => app.listen(port))
.catch((err) => {
  console.error(err);
  process.exit(1);
});
