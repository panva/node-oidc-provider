'use strict';

/* eslint-disable no-console */

const Provider = require('../lib');
const path = require('path');
const _ = require('lodash');
const bodyParser = require('koa-body');
const querystring = require('querystring');
const Router = require('koa-router');
const render = require('koa-ejs');

const port = process.env.PORT || 3000;

const Account = require('./account');
const settings = require('./settings');

const issuer = process.env.ISSUER || 'http://localhost:3000';

if (process.env.MONGODB_URI) {
  const MongoAdapter = require('./adapters/mongodb'); // eslint-disable-line global-require
  settings.config.adapter = MongoAdapter;
}

settings.config.findById = Account.findById;
const clients = settings.clients;

const provider = new Provider(issuer, settings.config);

if (process.env.HEROKU) {
  provider.defaultHttpOptions = { timeout: 15000 };
}

provider.initialize({
  clients,
  keystore: { keys: settings.certificates },
  integrity: { keys: settings.integrityKeys },
}).then(() => {
  render(provider.app, {
    cache: false,
    layout: '_layout',
    root: path.join(__dirname, 'views'),
  });

  provider.app.keys = ['some secret key', 'and also the old one'];

  if (process.env.NODE_ENV === 'production') {
    provider.app.proxy = true;
    _.set(settings.config, 'cookies.short.secure', true);
    _.set(settings.config, 'cookies.long.secure', true);

    provider.app.middleware.unshift(function* ensureSecure(next) {
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

  router.post('/interaction/:grant/confirm', body, function* submitConfirmationForm(next) {
    const result = { consent: {} };
    provider.interactionFinished(this.req, this.res, result);
    yield next;
  });

  router.post('/interaction/:grant/login', body, function* submitLoginForm() {
    const account = yield Account.findByLogin(this.request.body.login);

    const result = {
      login: {
        account: account.accountId,
        acr: 'urn:mace:incommon:iap:bronze',
        amr: ['pwd'],
        remember: !!this.request.body.remember,
        ts: Math.floor(Date.now() / 1000),
      },
      consent: {},
    };

    provider.interactionFinished(this.req, this.res, result);
  });

  provider.app.use(router.routes());
})
.then(() => provider.app.listen(port))
.catch((err) => {
  console.error(err);
  process.exit(1);
});
