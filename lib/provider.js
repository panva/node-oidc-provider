const url = require('url');
const assert = require('assert');
const { IncomingMessage, ServerResponse } = require('http');
const events = require('events');

const { get, merge } = require('lodash');
const Koa = require('koa');
const delegate = require('delegates');
const uuid = require('uuid/v4');
const semver = require('semver');

const pkg = require('../package.json');

const HTTP2_STABLE = semver.satisfies(process.version, '^8.13.0 || >=10.10.0');
let Http2ServerResponse;
let Http2ServerRequest;
/* istanbul ignore if */
if (HTTP2_STABLE) {
  ({ Http2ServerRequest, Http2ServerResponse } = require('http2')); // eslint-disable-line global-require
}

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
const getClaims = require('./helpers/claims');
const getContext = require('./helpers/oidc_context');
const { SessionNotFound } = require('./helpers/errors');
const models = require('./models');

function checkInit(provider) {
  assert(instance(provider).initialized, 'provider must be initialized first, see provider#initialize');
}

function getCookie(name, opts, cookies) {
  return cookies.get(name, opts);
}

function assertReqRes(req, res) {
  assert(
    req instanceof IncomingMessage
    || (HTTP2_STABLE && req instanceof Http2ServerRequest),
    'first argument must be the request (http.IncomingMessage || http2.Http2ServerRequest), for express req, for koa ctx.req',
  );
  if (arguments.length === 2) {
    assert(
      res instanceof ServerResponse
      || (HTTP2_STABLE && res instanceof Http2ServerResponse),
      'second argument must be the response (http.ServerResponse || http2.Http2ServerResponse), for express res, for koa ctx.res',
    );
  }
}

async function getInteraction(req, res) {
  assertReqRes.apply(undefined, arguments); // eslint-disable-line prefer-spread, prefer-rest-params
  const { cookies } = this.app.createContext(req, res);
  const id = getCookie.call(this, this.cookieName('interaction'), {
    signed: instance(this).configuration('cookies.short.signed'),
  }, cookies);
  if (!id) {
    throw new SessionNotFound('interaction session id cookie not found');
  }
  const interaction = await this.Session.find(id);
  if (!interaction) {
    throw new SessionNotFound('interaction session not found');
  }
  return interaction;
}

function defaultUserAgent(issuer) {
  return `${pkg.name}/${pkg.version} (${issuer})`;
}

class Provider extends events.EventEmitter {
  constructor(issuer, setup = {}) {
    assert(issuer, 'first argument must be the Issuer Identifier, i.e. https://op.example.com');
    assert.deepEqual(typeof issuer, 'string', 'Issuer Identifier must be a string');
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
      if (path) return get(conf, path);
      return conf;
    };

    const app = new Koa();
    if (Array.isArray(conf.cookies.keys) && conf.cookies.keys.length) {
      app.keys = conf.cookies.keys;
    } else {
      attention.warn('configuration cookies.keys is missing, this option is critical to detect and ignore tampered cookies');
    }

    instance(this).app = app;

    instance(this).defaultHttpOptions = {
      headers: { 'User-Agent': defaultUserAgent(this.issuer) },
      ...DEFAULT_HTTP_OPTIONS,
    };
    instance(this).responseModes = new Map();
    instance(this).grantTypeHandlers = new Map();
    instance(this).grantTypeDupes = new Map();
    instance(this).grantTypeParams = new Map([[undefined, new Set()]]);
    instance(this).Account = { findById: conf.findById };
    instance(this).Claims = getClaims(this);
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
    instance(this).DeviceCode = models.getDeviceCode(this);
    instance(this).OIDCContext = getContext(this);
    const { pathname } = url.parse(this.issuer);
    instance(this).mountPath = pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
  }

  initialize({ adapter, clients = [], keystore } = {}) {
    if (instance(this).initialized) throw new Error('already initialized');
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

  registerGrantType(name, handlerFactory, params, dupes) {
    instance(this).configuration('grantTypes').add(name);

    const { grantTypeHandlers, grantTypeParams, grantTypeDupes } = instance(this);

    const grantParams = new Set(['grant_type']);
    grantTypeHandlers.set(name, handlerFactory(this));
    if (dupes && typeof dupes === 'string') {
      grantTypeDupes.set(name, new Set([dupes]));
    } else if (dupes && (Array.isArray(dupes) || dupes instanceof Set)) {
      grantTypeDupes.set(name, new Set(dupes));
    }

    if (params && typeof params === 'string') {
      grantParams.add(params);
    } else if (params && (Array.isArray(params) || params instanceof Set)) {
      params.forEach(Set.prototype.add.bind(grantParams));
    }
    grantTypeParams.set(name, grantParams);
    grantParams.forEach(Set.prototype.add.bind(grantTypeParams.get(undefined)));
  }

  get OIDCContext() {
    return instance(this).OIDCContext;
  }

  cookieName(type) {
    const name = instance(this).configuration(`cookies.names.${type}`);
    assert(name, `cookie name for type ${type} is not configured`);
    return name;
  }

  registerResponseMode(name, handler) {
    const { responseModes } = instance(this);
    if (!responseModes.has(name)) {
      responseModes.set(name, handler.bind(this));
    }
  }

  pathFor(name, { mountPath = instance(this).mountPath, ...opts } = {}) {
    checkInit(this);
    const { router } = instance(this);

    const routerUrl = router.url(name, opts);
    if (routerUrl instanceof Error) throw routerUrl; // specific to koa-router

    return [mountPath, routerUrl].join('');
  }

  /**
   * @name interactionResult
   * @api public
   */
  async interactionResult(req, res, result) {
    const interaction = await getInteraction.call(this, req, res);
    interaction.result = result;
    await interaction.save(interaction.exp - epochTime());

    return interaction.returnTo;
  }

  /**
   * @name interactionFinished
   * @api public
   */
  async interactionFinished(req, res, result) {
    const returnTo = await this.interactionResult(req, res, result);

    res.statusCode = 302; // eslint-disable-line no-param-reassign
    res.setHeader('Location', returnTo);
    res.setHeader('Content-Length', '0');
    res.end();
  }

  /**
   * @name interactionDetails
   * @api public
   */
  async interactionDetails(req) {
    return getInteraction.call(this, req);
  }

  /**
   * @name setProviderSession
   * @api public
   */
  async setProviderSession(req, res, {
    account,
    ts = epochTime(),
    remember = true,
    clients = [],
    meta = {},
  } = {}) {
    assertReqRes(req, res);
    assert(typeof account === 'string', 'account must be a string');
    assert(Number.isSafeInteger(ts), 'ts must be an Integer');
    assert(Array.isArray(clients), 'clients must be an Array');

    const ctx = this.app.createContext(req, res);
    const session = await this.Session.get(ctx);

    Object.assign(session, { account, loginTs: ts });

    if (!remember) {
      session.transient = true;
    }

    clients.forEach((clientId) => {
      assert(typeof clientId === 'string', 'clients must contain an array of client_id strings');
      session.sidFor(clientId, uuid());
    });

    Object.entries(meta).forEach(([clientId, clientMeta]) => {
      assert(typeof clientId === 'string', 'meta must be an object of client_id strings as object keys');
      assert(clients.includes(clientId), 'meta client_id must be in clients');
      session.metaFor(clientId, clientMeta);
    });

    await session.save();

    const { maxAge, ...opts } = instance(this).configuration('cookies.long');

    ctx.cookies.set(this.cookieName('session'), session.id, session.transient ? opts : { maxAge, ...opts });

    return session;
  }

  httpOptions(values) {
    return merge({}, this.defaultHttpOptions, values);
  }

  use(fn) {
    instance(this).app.use(fn);
    if (instance(this).initialized) {
      // note: get the fn back since it might've been changed from generator to fn by koa-convert
      const newMw = instance(this).app.middleware.pop();
      const internalIndex = this.app.middleware.findIndex(mw => !!mw.firstInternal);
      this.app.middleware.splice(internalIndex, 0, newMw);
    }
  }

  get defaultHttpOptions() { return instance(this).defaultHttpOptions; }

  set defaultHttpOptions(value) {
    instance(this).defaultHttpOptions = merge({
      headers: { 'User-Agent': defaultUserAgent(this.issuer) },
    }, DEFAULT_HTTP_OPTIONS, value);
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

  get Claims() { return instance(this).Claims; }

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

  get DeviceCode() { return instance(this).DeviceCode; }

  static useGot() { // eslint-disable-line class-methods-use-this
    httpWrapper.useGot();
  }

  static useRequest() { // eslint-disable-line class-methods-use-this
    /* istanbul ignore next */
    httpWrapper.useRequest();
  }
}
Provider.useGot();

delegate(Provider.prototype, 'app')
  .access('env')
  .access('proxy')
  .access('subdomainOffset')
  .access('keys');

module.exports = Provider;
