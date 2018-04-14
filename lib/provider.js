const pkg = require('../package.json');

const assert = require('assert');
const Koa = require('koa');
const delegate = require('delegates');
const http = require('http');
const events = require('events');
const _ = require('lodash');
const url = require('url');
const { deprecate } = require('util');
const uuid = require('uuid/v4');

const { DEFAULT_HTTP_OPTIONS } = require('./consts');

const attention = require('./helpers/attention');
const getConfiguration = require('./helpers/configuration');
const instance = require('./helpers/weak_cache');
const initializeKeystore = require('./helpers/initialize_keystore');
const initializeAdapter = require('./helpers/initialize_adapter');
const initializeApp = require('./helpers/initialize_app');
const initializeClients = require('./helpers/initialize_clients');
const validUrl = require('./helpers/valid_url');
const epochTime = require('./helpers/epoch_time');
const httpWrapper = require('./helpers/http');
const errors = require('./helpers/errors');

const models = require('./models');

function checkInit(provider) {
  assert(provider.initialized, 'provider must be initialized first, see provider#initialize');
}

function getCookie(name, opts, cookies) {
  return cookies.get(name, opts);
}

function assertReqRes(req, res) {
  assert(
    req instanceof http.IncomingMessage,
    'first argument must be the request (http.IncomingMessage), for express req, for koa ctx.req',
  );
  if (arguments.length === 2) {
    assert(
      res instanceof http.ServerResponse,
      'second argument must be the response (http.ServerResponse), for express res, for koa ctx.res',
    );
  }
}

async function getSession(req, res) {
  assertReqRes(req, res);
  const ctx = this.app.createContext(req, res);
  return this.Session.get(ctx);
}

async function getInteraction(req, res) {
  assertReqRes.apply(undefined, arguments); // eslint-disable-line prefer-spread, prefer-rest-params
  const { cookies } = this.app.createContext(req, res);
  const id = getCookie.call(this, this.cookieName('interaction'), {
    signed: instance(this).configuration('cookies.short.signed'),
  }, cookies);
  const interaction = await this.Session.find(id);
  assert(interaction, 'interaction session not found');
  return interaction;
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

    const app = new Koa();
    if (Array.isArray(conf.cookies.keys) && conf.cookies.keys.length) {
      app.keys = conf.cookies.keys;
    } else {
      attention.warn('configuration cookies.keys is missing, this option is critical to detect and ignore tampered cookies');
    }
    instance(this).app = app;

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

  initialize({ adapter, clients = [], keystore } = {}) {
    if (this.initialized) throw new Error('already initialized');
    if (instance(this).initializing) {
      throw new Error('already initializing');
    } else {
      instance(this).initializing = true;
    }

    return initializeKeystore.call(this, keystore)
      .then(() => initializeAdapter.call(this, adapter))
      .then(() => initializeApp.call(this))
      .then(() => initializeClients.call(this, clients))
      .then(() => { instance(this).initialized = true; })
      .then(() => this)
      .catch((err) => {
        instance(this).initializing = false;
        throw err;
      });
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
    const interaction = await getInteraction.call(this, req, res);
    interaction.result = result;
    await interaction.save(60); // TODO: ttl read from the session

    res.statusCode = 302; // eslint-disable-line no-param-reassign
    res.setHeader('Location', interaction.returnTo);
    res.setHeader('Content-Length', '0');
    res.end();
  }

  async interactionDetails(req) {
    const interaction = await getInteraction.call(this, req);
    return interaction;
  }

  async setProviderSession(req, res, {
    account,
    ts = epochTime(),
    remember = true,
    clients = [],
  } = {}) {
    assert(typeof account === 'string', 'account must be a string');
    assert(Number.isInteger(ts), 'ts must be an Integer');
    assert(Array.isArray(clients), 'clients must be an Array');

    const session = await getSession.call(this, req, res);
    Object.assign(session, {
      account,
      loginTs: ts,
    });
    if (!remember) session.transient = true;
    clients.forEach((clientId) => {
      assert(typeof clientId === 'string', 'clients must contain an array of client_id strings');
      session.sidFor(clientId, uuid());
    });
    await session.save();
  }

  httpOptions(values) {
    return _.merge({
      headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${this.issuer}; ${pkg.homepage})` },
    }, this.defaultHttpOptions, values);
  }

  use(fn) {
    instance(this).app.use(fn);
    if (this.initialized) {
      // note: get the fn back since it might've been changed from generator to fn by koa-convert
      const newMw = instance(this).app.middleware.pop();
      const internalIndex = this.app.middleware.findIndex(mw => !!mw.firstInternal);
      this.app.middleware.splice(internalIndex, 0, newMw);
    }
  }

  get defaultHttpOptions() { return instance(this).defaultHttpOptions; }

  set defaultHttpOptions(value) {
    instance(this).defaultHttpOptions = _.merge({}, DEFAULT_HTTP_OPTIONS, value);
  }

  get app() {
    checkInit(this);
    return instance(this).app;
  }

  get callback() {
    return this.app.callback();
  }

  listen(...args) {
    /* istanbul ignore next */
    return this.app.listen(...args);
  }

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
  get initialized() { return !!instance(this).initialized; }

  static useGot() { // eslint-disable-line class-methods-use-this
    httpWrapper.useGot();
  }
  static useRequest() { // eslint-disable-line class-methods-use-this
    /* istanbul ignore next */
    httpWrapper.useRequest();
  }
}

// TODO: Deprecated, remove in 3.x
/* istanbul ignore next */
async function setSessionAccountId(req, id, ts = epochTime()) {
  assertReqRes(req);
  const { cookies } = this.app.createContext(req);
  const sessionId = getCookie.call(this, this.cookieName('session'), {
    signed: instance(this).configuration('cookies.long.signed'),
  }, cookies);
  const session = this.Session.find(sessionId);
  Object.assign(session, {
    account: id,
    loginTs: ts,
  });
  await session.save();
}
Provider.prototype.setSessionAccountId = deprecate(setSessionAccountId, 'setSessionAccountId is deprecated, use setProviderSession instead');

Object.assign(Provider, errors);

Provider.useGot();

delegate(Provider.prototype, 'app')
  .access('env')
  .access('proxy')
  .access('subdomainOffset')
  .access('keys');

module.exports = Provider;
