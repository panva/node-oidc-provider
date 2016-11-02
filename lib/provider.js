'use strict';

const pkg = require('../package.json');

const assert = require('assert');
const util = require('util');
const events = require('events');
const _ = require('lodash');
const url = require('url');

const DEFAULT_HTTP_OPTIONS = require('./consts').DEFAULT_HTTP_OPTIONS;

const getConfiguration = require('./helpers/configuration');
const instance = require('./helpers/weak_cache');
const initializeKeystore = require('./helpers/initialize_keystore');
const initializeIntegrity = require('./helpers/initialize_integrity');
const initializeApp = require('./helpers/initialize_app');
const initializeClients = require('./helpers/initialize_clients');

const models = require('./models');

function checkInit(provider) {
  assert(provider.initialized, 'provider must be initialized first, see provider#initialize');
}

class Provider extends events.EventEmitter {

  constructor(issuer, setup) {
    super();

    this.issuer = issuer;

    const conf = getConfiguration(setup);

    instance(this).configuration = function configuration(path) {
      if (path) return _.get(conf, path);
      return conf;
    };

    instance(this).initialized = false;
    instance(this).defaultHttpOptions = _.clone(DEFAULT_HTTP_OPTIONS);
    instance(this).responseModes = new Map();
    instance(this).grantTypeHandlers = new Map();
    instance(this).grantTypeWhitelist = new Set(['grant_type']);
    instance(this).mountPath = url.parse(this.issuer).pathname;
    instance(this).Account = { findById: conf.findById };

    instance(this).BaseToken = models.getBaseToken(this);
    instance(this).IdToken = models.getIdToken(this);
    instance(this).Client = models.getClient(this);
    instance(this).Session = models.getSession(this);
    instance(this).AccessToken = models.getAccessToken(this);
    instance(this).AuthorizationCode = models.getAuthorizationCode(this);
    instance(this).RefreshToken = models.getRefreshToken(this);
    instance(this).ClientCredentials = models.getClientCredentials(this);
    instance(this).InitialAccessToken = models.getInitialAccessToken(this);
    instance(this).RegistrationAccessToken = models.getRegistrationAccessToken(this);
  }

  initialize(args) {
    if (this.initialized) throw new Error('already initialized');

    const keysAndClients = (() => {
      if (args) return args;
      return {};
    })();

    return initializeKeystore.call(this, keysAndClients.keystore)
      .then(() => initializeIntegrity.call(this, keysAndClients.integrity))
      .then(() => initializeApp.call(this))
      .then(() => initializeClients.call(this, keysAndClients.clients))
      .then(() => { instance(this).initialized = true; })
      .then(() => this);
  }

  urlFor(name, opt) { return url.resolve(this.issuer, this.pathFor(name, opt)); }

  registerGrantType(name, handlerFactory, params) {
    instance(this).configuration('grantTypes').add(name);

    const grantTypeHandlers = instance(this).grantTypeHandlers;
    const grantTypeWhitelist = instance(this).grantTypeWhitelist;

    grantTypeHandlers.set(name, handlerFactory(this));

    switch (typeof params) {
      case 'undefined':
        break;
      case 'string':
        if (params) grantTypeWhitelist.add(params);
        break;
      default:
        if (params && params.forEach) {
          params.forEach(grantTypeWhitelist.add.bind(grantTypeWhitelist));
        }
    }
  }

  registerResponseMode(name, handler) { instance(this).responseModes.set(name, handler); }

  pathFor(name, opts) {
    checkInit(this);
    const mountPath = (opts && opts.mountPath) || instance(this).mountPath;
    const router = instance(this).router;
    return [mountPath !== '/' ? mountPath : undefined, router.url(name, opts)].join('');
  }

  resume(ctx, grant, result) {
    const resumeUrl = this.urlFor('resume', { grant });
    const path = url.parse(resumeUrl).pathname;
    const opts = _.merge({ path }, instance(this).configuration('cookies.short'));

    ctx.cookies.set('_grant_result', JSON.stringify(result), opts);
    ctx.redirect(resumeUrl);
  }

  httpOptions(values) {
    return _.merge({
      headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${this.issuer}; ${pkg.homepage})` },
    }, this.defaultHttpOptions, values);
  }

  get defaultHttpOptions() { return instance(this).defaultHttpOptions; }

  set defaultHttpOptions(value) {
    instance(this).defaultHttpOptions = _.merge({}, DEFAULT_HTTP_OPTIONS, value);
  }

  get app() { checkInit(this); return instance(this).app; }
  get callback() { /* istanbul ignore next */ return this.app.callback(); }
  get BaseToken() { return instance(this).BaseToken; }
  get Account() { return instance(this).Account; }
  get IdToken() { return instance(this).IdToken; }
  get Client() { return instance(this).Client; }
  get Session() { return instance(this).Session; }
  get AccessToken() { return instance(this).AccessToken; }
  get AuthorizationCode() { return instance(this).AuthorizationCode; }
  get RefreshToken() { return instance(this).RefreshToken; }
  get ClientCredentials() { return instance(this).ClientCredentials; }
  get InitialAccessToken() { return instance(this).InitialAccessToken; }
  get RegistrationAccessToken() { return instance(this).RegistrationAccessToken; }
  get initialized() { return instance(this).initialized; }
}

Object.defineProperty(Provider.prototype, 'OAuthToken', {
  get: util.deprecate(/* istanbul ignore next */ function OAuthTokenGetter() {
    return this.BaseToken;
  }, 'provider#OAuthToken renamed to provider#BaseToken'),
});

module.exports = Provider;
