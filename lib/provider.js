import { strict as assert } from 'node:assert';
import * as util from 'node:util';

import QuickLRU from 'quick-lru';
import Koa from 'koa';

import Configuration from './helpers/configuration.js';
import * as instance from './helpers/weak_cache.js';
import inititalizeKeyStore from './helpers/initialize_keystore.js';
import initializeAdapter from './helpers/initialize_adapter.js';
import initializeApp from './helpers/initialize_app.js';
import initializeClients from './helpers/initialize_clients.js';
import ResourceServer from './helpers/resource_server.js';
import { isWebUri } from './helpers/valid_url.js';
import epochTime from './helpers/epoch_time.js';
import getClaims from './helpers/claims.js';
import getContext from './helpers/oidc_context.js';
import { SessionNotFound, OIDCProviderError } from './helpers/errors.js';
import * as models from './models/index.js';
import ServerChallenge from './helpers/challenge.js';
import als from './helpers/als.js';

export class Provider extends Koa {
  #AccessToken;

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

  #exec;

  #int = {
    dynamicClients: new QuickLRU({ maxSize: 100 }),
  };

  constructor(issuer, setup) {
    assert(issuer, 'first argument must be the Issuer Identifier, i.e. https://op.example.com');
    assert.equal(typeof issuer, 'string', 'Issuer Identifier must be a string');
    assert(isWebUri(issuer), 'Issuer Identifier must be a valid web uri');

    const {
      pathname, host, protocol, search, hash, href,
    } = new URL(issuer);
    assert(host, 'Issuer Identifier must have a host component');
    assert(protocol, 'Issuer Identifier must have an URI scheme component');
    assert(!search && !href.endsWith('?'), 'Issuer Identifier must not have a query component');
    assert(!hash && !href.endsWith('#'), 'Issuer Identifier must not have a fragment component');

    super();

    this.issuer = issuer;

    const configuration = new Configuration(setup);
    instance.set(this, this.#int);

    this.#int.configuration = configuration;
    this.#int.features = configuration.features;

    if (Array.isArray(configuration.cookies.keys)) {
      if (configuration.cookies.keys.length) {
        this.keys = configuration.cookies.keys;
      }
    } else if (configuration.cookies.keys) {
      this.keys = configuration.cookies.keys;
    }

    if (
      configuration.features.dPoP.enabled
      && configuration.features.dPoP.nonceSecret !== undefined
    ) {
      try {
        this.#int.DPoPNonces = new ServerChallenge(configuration.features.dPoP.nonceSecret, 'DPoP');
      } catch (cause) {
        throw new TypeError('features.dPoP.nonceSecret secret must be a 32-byte Buffer instance', { cause });
      }
    }

    if (configuration.features.attestClientAuth.enabled) {
      try {
        this.#int.AttestChallenges = new ServerChallenge(
          configuration.features.attestClientAuth.challengeSecret,
          'OAuth-Client-Attestation-PoP',
        );
      } catch (cause) {
        throw new TypeError('features.attestClientAuth.challengeSecret secret must be a 32-byte Buffer instance', { cause });
      }
    }

    this.#int.responseModes = new Map();
    this.#int.grantTypeHandlers = new Map();
    this.#int.grantTypeDupes = new Map();
    this.#int.grantTypeParams = new Map([[undefined, new Set()]]);
    this.#int.BaseModel = models.getBaseModel(this);

    this.#mountPath = pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;

    initializeAdapter.call(this, configuration.adapter);

    inititalizeKeyStore.call(this, configuration.jwks);
    delete configuration.jwks;

    this.#exec = initializeApp.call(this);
    Koa.prototype.use.call(this, this.#exec);

    initializeClients.call(this, configuration.clients);
    delete configuration.clients;
  }

  urlFor(name, opt) {
    return new URL(this.pathFor(name, opt), this.issuer).href;
  }

  registerGrantType(name, handler, params, dupes) {
    this.#int.configuration.grantTypes.add(name);

    const { grantTypeHandlers, grantTypeParams, grantTypeDupes } = this.#int;

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
    const name = this.#int.configuration.cookies.names[type];
    if (!name) {
      throw new Error(`cookie name for type ${type} is not configured`);
    }
    return name;
  }

  registerResponseMode(name, handler) {
    const { responseModes } = this.#int;
    if (!responseModes.has(name)) {
      responseModes.set(name, handler.bind(this));
    }
  }

  pathFor(name, { mountPath = this.#mountPath, ...opts } = {}) {
    const routerUrl = this.#int.router.url(name, opts);

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
    const interaction = await this.#getInteraction.call(this, req, res);

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
    return this.#getInteraction.call(this, req, res);
  }

  async backchannelResult(request, result, {
    acr,
    amr,
    authTime,
    sessionUid,
    expiresWithSession,
    sid,
    rar,
  } = {}) {
    if (typeof request === 'string' && request) {
      // eslint-disable-next-line no-param-reassign
      request = await this.BackchannelAuthenticationRequest.find(request, {
        ignoreExpiration: true,
      });
      if (!request) {
        throw new Error('BackchannelAuthenticationRequest not found');
      }
    } else if (!(request instanceof this.BackchannelAuthenticationRequest)) {
      throw new TypeError('invalid "request" argument');
    }

    const client = await this.Client.find(request.clientId);
    if (!client) {
      throw new Error('Client not found');
    }

    if (typeof result === 'string' && result) {
      // eslint-disable-next-line no-param-reassign
      result = await this.Grant.find(result);
      if (!result) {
        throw new Error('Grant not found');
      }
    }

    switch (true) {
      case result instanceof this.Grant:
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
          rar,
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

  get OIDCContext() {
    this.#OIDCContext ||= getContext(this);
    return this.#OIDCContext;
  }

  get Claims() {
    this.#Claims ||= getClaims(this);
    return this.#Claims;
  }

  get BaseToken() {
    this.#BaseToken ||= models.getBaseToken(this);
    return this.#BaseToken;
  }

  get IdToken() {
    this.#IdToken ||= models.getIdToken(this);
    return this.#IdToken;
  }

  get Client() {
    this.#Client ||= models.getClient(this);
    return this.#Client;
  }

  get Grant() {
    this.#Grant ||= models.getGrant(this);
    return this.#Grant;
  }

  get Session() {
    this.#Session ||= models.getSession(this);
    return this.#Session;
  }

  get Interaction() {
    this.#Interaction ||= models.getInteraction(this);
    return this.#Interaction;
  }

  get AccessToken() {
    this.#AccessToken ||= models.getAccessToken(this);
    return this.#AccessToken;
  }

  get AuthorizationCode() {
    this.#AuthorizationCode ||= models.getAuthorizationCode(this);
    return this.#AuthorizationCode;
  }

  get RefreshToken() {
    this.#RefreshToken ||= models.getRefreshToken(this);
    return this.#RefreshToken;
  }

  get ClientCredentials() {
    this.#ClientCredentials ||= models.getClientCredentials(this);
    return this.#ClientCredentials;
  }

  get InitialAccessToken() {
    this.#InitialAccessToken ||= models.getInitialAccessToken(this);
    return this.#InitialAccessToken;
  }

  get RegistrationAccessToken() {
    this.#RegistrationAccessToken ||= models.getRegistrationAccessToken(this);
    return this.#RegistrationAccessToken;
  }

  get DeviceCode() {
    this.#DeviceCode ||= models.getDeviceCode(this);
    return this.#DeviceCode;
  }

  get BackchannelAuthenticationRequest() {
    this.#BackchannelAuthenticationRequest ||= models.getBackchannelAuthenticationRequest(this);
    return this.#BackchannelAuthenticationRequest;
  }

  get PushedAuthorizationRequest() {
    this.#PushedAuthorizationRequest ||= models.getPushedAuthorizationRequest(this);
    return this.#PushedAuthorizationRequest;
  }

  get ReplayDetection() {
    this.#ReplayDetection ||= models.getReplayDetection(this);
    return this.#ReplayDetection;
  }

  // eslint-disable-next-line class-methods-use-this
  get ResourceServer() { return ResourceServer; }

  async #getInteraction(req, res) {
    const ctx = this.createContext(req, res);
    const id = ctx.cookies.get(
      this.cookieName('interaction'),
      this.#int.configuration.cookies.short,
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

  use(fn) {
    Koa.prototype.use.call(this, fn);
    this.middleware.splice(this.middleware.indexOf(this.#exec), 0, this.middleware.pop());
    return this;
  }

  // eslint-disable-next-line class-methods-use-this
  get [Symbol.toStringTag]() {
    return 'Provider';
  }

  toJSON() {
    return { issuer: this.issuer };
  }

  inspect() {
    return `[${this[Symbol.toStringTag]} ${this.issuer}]`;
  }

  static get ctx() {
    return als.getStore();
  }
}

Object.defineProperty(Provider.prototype, 'app', {
  get: util.deprecate(function app() {
    return this;
  }, '.app getter is deprecated. The Provider instance is now the Koa app itself'),
});
