// eslint-disable-next-line import/order
const attention = require('./helpers/attention');

const minimal = 'Erbium';
const current = process.release.lts;
if (!current || current.charCodeAt(0) < minimal.charCodeAt(0)) {
  attention.warn('Unsupported Node.js runtime version.');
}

const url = require('url');
const { strict: assert } = require('assert');
const { IncomingMessage, ServerResponse } = require('http');
const { Http2ServerRequest, Http2ServerResponse } = require('http2');
const events = require('events');

const Koa = require('koa');

const Configuration = require('./helpers/configuration');
const { ROUTER_URL_METHOD } = require('./helpers/symbols');
const instance = require('./helpers/weak_cache');
const initializeKeystore = require('./helpers/initialize_keystore');
const initializeAdapter = require('./helpers/initialize_adapter');
const initializeApp = require('./helpers/initialize_app');
const initializeClients = require('./helpers/initialize_clients');
const RequestUriCache = require('./helpers/request_uri_cache');
const ResourceServer = require('./helpers/resource_server');
const validUrl = require('./helpers/valid_url');
const epochTime = require('./helpers/epoch_time');
const getClaims = require('./helpers/claims');
const getContext = require('./helpers/oidc_context');
const { SessionNotFound, OIDCProviderError } = require('./helpers/errors');
const models = require('./models');
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
    if (interaction.session.accountId !== session.accountId) {
      throw new SessionNotFound('session principal changed');
    }
  }

  return interaction;
}

class Provider extends events.EventEmitter {
  #AccessToken;

  #Account;

  #app = new Koa();

  #AuthorizationCode;

  #BaseToken;

  #Claims;

  #Client;

  #ClientCredentials;

  #DeviceCode;

  #BackchannelAuthenticationRequest;

  #Grant;

  #IdToken;

  #InitialAccessToken;

  #Interaction;

  #mountPath;

  #OIDCContext;

  #PushedAuthorizationRequest;

  #RefreshToken;

  #RegistrationAccessToken;

  #ReplayDetection;

  #Session;

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

    if (Array.isArray(configuration.cookies.keys) && configuration.cookies.keys.length) {
      this.#app.keys = configuration.cookies.keys;
    } else {
      attention.warn('configuration cookies.keys is missing, this option is critical to detect and ignore tampered cookies');
    }

    instance(this).responseModes = new Map();
    instance(this).grantTypeHandlers = new Map();
    instance(this).grantTypeDupes = new Map();
    instance(this).grantTypeParams = new Map([[undefined, new Set()]]);
    this.#Account = { findAccount: configuration.findAccount };
    this.#Claims = getClaims(this);
    instance(this).BaseModel = models.getBaseModel(this);
    this.#BaseToken = models.getBaseToken(this);
    this.#IdToken = models.getIdToken(this);
    this.#Client = models.getClient(this);
    this.#Grant = models.getGrant(this);
    this.#Session = models.getSession(this);
    this.#Interaction = models.getInteraction(this);
    this.#AccessToken = models.getAccessToken(this);
    this.#AuthorizationCode = models.getAuthorizationCode(this);
    this.#RefreshToken = models.getRefreshToken(this);
    this.#ClientCredentials = models.getClientCredentials(this);
    this.#InitialAccessToken = models.getInitialAccessToken(this);
    this.#RegistrationAccessToken = models.getRegistrationAccessToken(this);
    this.#ReplayDetection = models.getReplayDetection(this);
    this.#DeviceCode = models.getDeviceCode(this);
    this.#BackchannelAuthenticationRequest = models.getBackchannelAuthenticationRequest(this);
    this.#PushedAuthorizationRequest = models.getPushedAuthorizationRequest(this);
    this.#OIDCContext = getContext(this);
    const { pathname } = url.parse(this.issuer);
    this.#mountPath = pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
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

  pathFor(name, { mountPath = this.#mountPath, ...opts } = {}) {
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

    res.statusCode = 303; // eslint-disable-line no-param-reassign
    res.setHeader('Location', returnTo);
    res.setHeader('Content-Length', '0');
    res.end();
  }

  /**
   * @name interactionDetails
   * @api public
   */
  async interactionDetails(req, res) {
    return getInteraction.call(this, req, res);
  }

  async backchannelResult(request, result, {
    acr,
    amr,
    authTime,
    sessionUid,
    expiresWithSession,
    sid,
  } = {}) {
    if (typeof request === 'string' && request) {
      // eslint-disable-next-line no-param-reassign
      request = await this.#BackchannelAuthenticationRequest.find(request, {
        ignoreExpiration: true,
      });
      if (!request) {
        throw new Error('BackchannelAuthenticationRequest not found');
      }
    } else if (!(request instanceof this.#BackchannelAuthenticationRequest)) {
      throw new TypeError('invalid "request" argument');
    }

    const client = await this.#Client.find(request.clientId);
    if (!client) {
      throw new Error('Client not found');
    }

    if (typeof result === 'string' && result) {
      // eslint-disable-next-line no-param-reassign
      result = await this.#Grant.find(result);
      if (!result) {
        throw new Error('Grant not found');
      }
    }

    switch (true) {
      case result instanceof this.#Grant:
        if (request.clientId !== result.clientId) {
          throw new Error('client mismatch');
        }

        if (request.accountId !== result.accountId) {
          throw new Error('accountId mismatch');
        }

        Object.assign(request, {
          grantId: result.jti,
          acr,
          amr,
          authTime,
          sessionUid,
          expiresWithSession,
          sid,
        });
        break;
      case result instanceof OIDCProviderError:
        Object.assign(request, {
          error: result.error,
          error_description: result.error_description,
        });
        break;
      default:
        throw new TypeError('invalid "result" argument');
    }

    await request.save();

    if (client.backchannelTokenDeliveryMode === 'ping') {
      await client.backchannelPing(request);
    }
  }

  use(fn) {
    this.#app.use(fn);
    // note: get the fn back since it might've been changed from generator to fn by koa-convert
    const newMw = this.#app.middleware.pop();
    const internalIndex = this.#app.middleware.findIndex((mw) => !!mw.firstInternal);
    this.#app.middleware.splice(internalIndex, 0, newMw);
  }

  get app() {
    return this.#app;
  }

  callback() {
    return this.#app.callback();
  }

  listen(...args) {
    return this.#app.listen(...args);
  }

  get proxy() {
    return this.#app.proxy;
  }

  set proxy(value) {
    this.#app.proxy = value;
  }

  get OIDCContext() { return this.#OIDCContext; }

  get Claims() { return this.#Claims; }

  get BaseToken() { return this.#BaseToken; }

  get Account() { return this.#Account; }

  get IdToken() { return this.#IdToken; }

  get Client() { return this.#Client; }

  get Grant() { return this.#Grant; }

  get Session() { return this.#Session; }

  get Interaction() { return this.#Interaction; }

  get AccessToken() { return this.#AccessToken; }

  get AuthorizationCode() { return this.#AuthorizationCode; }

  get RefreshToken() { return this.#RefreshToken; }

  get ClientCredentials() { return this.#ClientCredentials; }

  get InitialAccessToken() { return this.#InitialAccessToken; }

  get RegistrationAccessToken() { return this.#RegistrationAccessToken; }

  get DeviceCode() { return this.#DeviceCode; }

  get BackchannelAuthenticationRequest() { return this.#BackchannelAuthenticationRequest; }

  get PushedAuthorizationRequest() { return this.#PushedAuthorizationRequest; }

  get ReplayDetection() { return this.#ReplayDetection; }

  // eslint-disable-next-line class-methods-use-this
  get ResourceServer() { return ResourceServer; }
}

module.exports = Provider;
