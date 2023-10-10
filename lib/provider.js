// eslint-disable-next-line import/order
import * as attention from './helpers/attention.js';

import * as url from 'node:url';
import { strict as assert } from 'node:assert';
import * as events from 'node:events';

import Koa from 'koa';

import Configuration from './helpers/configuration.js';
import instance from './helpers/weak_cache.js';
import initializeKeystore from './helpers/initialize_keystore.js';
import initializeAdapter from './helpers/initialize_adapter.js';
import initializeApp from './helpers/initialize_app.js';
import initializeClients from './helpers/initialize_clients.js';
import RequestUriCache from './helpers/request_uri_cache.js';
import ResourceServer from './helpers/resource_server.js';
import { isWebUri } from './helpers/valid_url.js';
import epochTime from './helpers/epoch_time.js';
import getClaims from './helpers/claims.js';
import getContext from './helpers/oidc_context.js';
import { SessionNotFound, OIDCProviderError } from './helpers/errors.js';
import * as models from './models/index.js';
import * as ssHandler from './helpers/samesite_handler.js';
import get from './helpers/_/get.js';
import DPoPNonces from './helpers/dpop_nonces.js';

async function getInteraction(req, res) {
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

  if (interaction.session?.uid) {
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
    assert(isWebUri(issuer), 'Issuer Identifier must be a valid web uri');

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

    if (configuration.features.dPoP.nonceSecret !== undefined) {
      instance(this).DPoPNonces = new DPoPNonces(configuration.features.dPoP.nonceSecret);
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
    if (!name) {
      throw new Error(`cookie name for type ${type} is not configured`);
    }
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

    const routerUrl = router.url(name, opts);

    if (routerUrl instanceof Error) {
      throw routerUrl;
    }

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

export default Provider;
