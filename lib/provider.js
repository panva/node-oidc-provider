const pkg = require('../package.json');

const assert = require('assert');
const http = require('http');
const events = require('events');
const _ = require('lodash');
const url = require('url');
const validUrl = require('valid-url');

const { DEFAULT_HTTP_OPTIONS } = require('./consts');

const getConfiguration = require('./helpers/configuration');
const instance = require('./helpers/weak_cache');
const initializeKeystore = require('./helpers/initialize_keystore');
const initializeAdapter = require('./helpers/initialize_adapter');
const initializeApp = require('./helpers/initialize_app');
const initializeClients = require('./helpers/initialize_clients');

const models = require('./models');

function checkInit(provider) {
  assert(provider.initialized, 'provider must be initialized first, see provider#initialize');
}

function grantCookie(cookies) {
  try {
    return cookies.get(this.cookieName('interaction'), {
      signed: instance(this).configuration('cookies.short.signed'),
    });
  } catch (err) {
    /* istanbul ignore next */
    throw new Error('interaction cookie manipulated, expired or otherwise not received');
  }
}

class Provider extends events.EventEmitter {

  constructor(issuer, setup = {}) {
    assert(issuer, 'first argument must be the Issuer Identifier, i.e. https://op.example.com');
    assert.equal(typeof issuer, 'string', 'Issuer Identifier must be a string');
    assert(validUrl.isWebUri(issuer), 'Issuer Identifier must be a valid web uri');

    const components = url.parse(issuer);
    assert(components.host, 'Issuer Identifier must have a host component');
    assert(components.protocol, 'Issuer Identifier must have an URI scheme component');
    assert(!components.search, 'Issuer Identifier must not have a query component');
    assert(!components.hash, 'Issuer Identifier must not have a fragment component');

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

  initialize(args = {}) {
    if (this.initialized) throw new Error('already initialized');

    return initializeKeystore.call(this, args.keystore)
      .then(() => initializeAdapter.call(this, args.adapter))
      .then(() => initializeApp.call(this))
      .then(() => initializeClients.call(this, args.clients))
      .then(() => { instance(this).initialized = true; })
      .then(() => this);
  }

  urlFor(name, opt) { return url.resolve(this.issuer, this.pathFor(name, opt)); }

  registerGrantType(name, handlerFactory, params) {
    instance(this).configuration('grantTypes').add(name);

    const { grantTypeHandlers, grantTypeWhitelist } = instance(this);

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

  cookieName(type) {
    const name = instance(this).configuration(`cookies.names.${type}`);
    assert(name, `cookie name for type ${type} is not configured`);
    return name;
  }

  registerResponseMode(name, handler) { instance(this).responseModes.set(name, handler); }

  pathFor(name, opts) {
    checkInit(this);
    const mountPath = (opts && opts.mountPath) || instance(this).mountPath;
    const { router } = instance(this);

    const routerUrl = router.url(name, opts);
    if (routerUrl instanceof Error) throw routerUrl; // specific to koa-router

    return [mountPath !== '/' ? mountPath : undefined, routerUrl].join('');
  }

  async interactionFinished(req, res, result) {
    assert(req instanceof http.IncomingMessage,
      'first argument must be the request (http.IncomingMessage), for express req, for koa ctx.req');
    assert(res instanceof http.ServerResponse,
      'second argument must be the response (http.ServerResponse), for express res, for koa ctx.res');

    const { cookies } = this.app.createContext(req, res);
    const interaction = await this.Session.find(grantCookie.call(this, cookies));
    if (!interaction) {
      throw new Error('interaction session not found');
    }

    interaction.result = result;
    await interaction.save(60); // TODO: ttl read from the session

    res.statusCode = 302; // eslint-disable-line no-param-reassign
    res.setHeader('Location', interaction.returnTo);
    res.setHeader('Content-Length', '0');
    res.end();
  }

  async interactionDetails(req) {
    assert(req instanceof http.IncomingMessage,
      'first argument must be the request, for express req, for koa ctx.req');

    const id = grantCookie.call(this, this.app.createContext(req).cookies);

    return this.Session.find(id);
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

module.exports = Provider;
