const url = require('url');
const { strict: assert } = require('assert');
const { IncomingMessage, ServerResponse } = require('http');
const { Http2ServerRequest, Http2ServerResponse } = require('http2');
const events = require('events');

const Koa = require('koa');

const attention = require('./helpers/attention');
const Configuration = require('./helpers/configuration');
const { ROUTER_URL_METHOD } = require('./helpers/symbols');
const instance = require('./helpers/weak_cache');
const initializeKeystore = require('./helpers/initialize_keystore');
const initializeAdapter = require('./helpers/initialize_adapter');
const initializeApp = require('./helpers/initialize_app');
const initializeClients = require('./helpers/initialize_clients');
const RequestUriCache = require('./helpers/request_uri_cache');
const validUrl = require('./helpers/valid_url');
const epochTime = require('./helpers/epoch_time');
const getClaims = require('./helpers/claims');
const getContext = require('./helpers/oidc_context');
const { SessionNotFound } = require('./helpers/errors');
const models = require('./models');
const nanoid = require('./helpers/nanoid');
const ssHandler = require('./helpers/samesite_handler');
const get = require('./helpers/_/get');

function assertReqRes(req, res) {
  assert(
    req instanceof IncomingMessage || req instanceof Http2ServerRequest,
    'first argument must be the request (http.IncomingMessage || http2.Http2ServerRequest), for express req, for koa ctx.req',
  );
  if (arguments.length === 2) {
    assert(
      res instanceof ServerResponse || res instanceof Http2ServerResponse,
      'second argument must be the response (http.ServerResponse || http2.Http2ServerResponse), for express res, for koa ctx.res',
    );
  }
}

async function getInteraction(req, res) {
  assertReqRes.apply(undefined, arguments); // eslint-disable-line prefer-spread, prefer-rest-params
  const ctx = this.app.createContext(req, res);
  const id = ssHandler.get(
    ctx.cookies,
    this.cookieName('interaction'),
    instance(this).configuration('cookies.short'),
  );
  if (!id) {
    throw new SessionNotFound('interaction session id cookie not found');
  }
  const interaction = await this.Interaction.find(id);
  if (!interaction) {
    throw new SessionNotFound('interaction session not found');
  }

  if (interaction.session && interaction.session.uid) {
    const session = await this.Session.findByUid(interaction.session.uid);
    if (!session) {
      throw new SessionNotFound('session not found');
    }
    if (interaction.session.accountId !== session.accountId()) {
      throw new SessionNotFound('session principal changed');
    }
  }

  return interaction;
}

class Provider extends events.EventEmitter {
  constructor(issuer, setup) {
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

    const configuration = new Configuration(setup);

    instance(this).configuration = (path) => {
      if (path) return get(configuration, path);
      return configuration;
    };

    const app = new Koa();

    if (Array.isArray(configuration.cookies.keys) && configuration.cookies.keys.length) {
      app.keys = configuration.cookies.keys;
    } else {
      attention.warn('configuration cookies.keys is missing, this option is critical to detect and ignore tampered cookies');
    }

    instance(this).app = app;
    instance(this).responseModes = new Map();
    instance(this).grantTypeHandlers = new Map();
    instance(this).grantTypeDupes = new Map();
    instance(this).grantTypeParams = new Map([[undefined, new Set()]]);
    instance(this).Account = { findAccount: configuration.findAccount };
    instance(this).Claims = getClaims(this);
    instance(this).BaseModel = models.getBaseModel(this);
    instance(this).BaseToken = models.getBaseToken(this);
    instance(this).IdToken = models.getIdToken(this);
    instance(this).Client = models.getClient(this);
    instance(this).Session = models.getSession(this);
    instance(this).Interaction = models.getInteraction(this);
    instance(this).AccessToken = models.getAccessToken(this);
    instance(this).AuthorizationCode = models.getAuthorizationCode(this);
    instance(this).RefreshToken = models.getRefreshToken(this);
    instance(this).ClientCredentials = models.getClientCredentials(this);
    instance(this).InitialAccessToken = models.getInitialAccessToken(this);
    instance(this).RegistrationAccessToken = models.getRegistrationAccessToken(this);
    instance(this).ReplayDetection = models.getReplayDetection(this);
    instance(this).DeviceCode = models.getDeviceCode(this);
    instance(this).PushedAuthorizationRequest = models.getPushedAuthorizationRequest(this);
    instance(this).OIDCContext = getContext(this);
    const { pathname } = url.parse(this.issuer);
    instance(this).mountPath = pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
    instance(this).requestUriCache = new RequestUriCache(this);

    initializeAdapter.call(this, configuration.adapter);
    initializeKeystore.call(this, configuration.jwks);
    delete configuration.jwks;
    initializeApp.call(this);
    initializeClients.call(this, configuration.clients);
    delete configuration.clients;
  }

  urlFor(name, opt) { return url.resolve(this.issuer, this.pathFor(name, opt)); }

  registerGrantType(name, handler, params, dupes) {
    instance(this).configuration('grantTypes').add(name);

    const { grantTypeHandlers, grantTypeParams, grantTypeDupes } = instance(this);

    const grantParams = new Set(['grant_type']);
    grantTypeHandlers.set(name, handler);

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
    const { router } = instance(this);

    const routerUrl = router[ROUTER_URL_METHOD](name, opts);

    return [mountPath, routerUrl].join('');
  }

  /**
   * @name interactionResult
   * @api public
   */
  async interactionResult(req, res, result, { mergeWithLastSubmission = true } = {}) {
    const interaction = await getInteraction.call(this, req, res);

    if (mergeWithLastSubmission && !('error' in result)) {
      interaction.result = { ...interaction.lastSubmission, ...result };
    } else {
      interaction.result = result;
    }

    await interaction.save(interaction.exp - epochTime());

    return interaction.returnTo;
  }

  /**
   * @name interactionFinished
   * @api public
   */
  async interactionFinished(req, res, result, { mergeWithLastSubmission = true } = {}) {
    const returnTo = await this.interactionResult(req, res, result, { mergeWithLastSubmission });

    res.statusCode = 302; // eslint-disable-line no-param-reassign
    res.setHeader('Location', returnTo);
    res.setHeader('Content-Length', '0');
    res.end();
  }

  /**
   * @name interactionDetails
   * @api public
   */
  async interactionDetails(req, res) {
    /* istanbul ignore if */
    if (typeof res === 'undefined') { // TODO: in v7.x deprecate only req
      return getInteraction.call(this, req);
    }

    return getInteraction.call(this, req, res);
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

    const ctx = {
      oidc: {
        cookies: this.app.createContext(req, res).cookies,
      },
      secure: req.connection.encrypted || req.protocol === 'https',
    };

    const session = await this.Session.get(ctx);

    Object.assign(session, { account, loginTs: ts });

    if (!remember) {
      session.transient = true;
    }

    clients.forEach((clientId) => {
      assert(typeof clientId === 'string', 'clients must contain an array of client_id strings');
      session.sidFor(clientId, nanoid());
      session.grantIdFor(clientId, nanoid());
    });

    Object.entries(meta).forEach(([clientId, clientMeta]) => {
      assert(typeof clientId === 'string', 'meta must be an object of client_id strings as object keys');
      assert(clients.includes(clientId), 'meta client_id must be in clients');
      session.metaFor(clientId, clientMeta);
    });

    await session.save();

    const { maxAge, ...opts } = instance(this).configuration('cookies.long');

    ssHandler.set(
      ctx.oidc.cookies,
      this.cookieName('session'),
      session.id,
      session.transient ? opts : { maxAge, ...opts },
    );

    return session;
  }

  use(fn) {
    instance(this).app.use(fn);
    // note: get the fn back since it might've been changed from generator to fn by koa-convert
    const newMw = instance(this).app.middleware.pop();
    const internalIndex = this.app.middleware.findIndex((mw) => !!mw.firstInternal);
    this.app.middleware.splice(internalIndex, 0, newMw);
  }

  get app() {
    return instance(this).app;
  }

  // TODO: in v7.x make this a function
  get callback() {
    return this.app.callback();
  }

  /* istanbul ignore next */
  listen(...args) {
    return this.app.listen(...args);
  }

  get Claims() { return instance(this).Claims; }

  get BaseToken() { return instance(this).BaseToken; }

  get Account() { return instance(this).Account; }

  get IdToken() { return instance(this).IdToken; }

  get Client() { return instance(this).Client; }

  get Session() { return instance(this).Session; }

  get Interaction() { return instance(this).Interaction; }

  get AccessToken() { return instance(this).AccessToken; }

  get AuthorizationCode() { return instance(this).AuthorizationCode; }

  get RefreshToken() { return instance(this).RefreshToken; }

  get ClientCredentials() { return instance(this).ClientCredentials; }

  get InitialAccessToken() { return instance(this).InitialAccessToken; }

  get RegistrationAccessToken() { return instance(this).RegistrationAccessToken; }

  get DeviceCode() { return instance(this).DeviceCode; }

  get PushedAuthorizationRequest() { return instance(this).PushedAuthorizationRequest; }

  get ReplayDetection() { return instance(this).ReplayDetection; }

  get requestUriCache() { return instance(this).requestUriCache; }
}

/* istanbul ignore next */
['env', 'proxy', 'subdomainOffset', 'keys', 'proxyIpHeader', 'maxIpsCount'].forEach((method) => {
  Object.defineProperty(Provider.prototype, method, {
    get() {
      return this.app[method];
    },
    set(value) {
      this.app[method] = value;
    },
  });
});

module.exports = Provider;
