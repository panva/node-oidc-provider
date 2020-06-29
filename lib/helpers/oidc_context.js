const events = require('events');
const url = require('url');
const { deprecate } = require('util');

const debug = require('debug')('oidc-provider:bearer');
const { JWT, JWK } = require('jose');

const ctxRef = require('../models/ctx_ref');

const get = require('./_/get');
const isPlainObject = require('./_/is_plain_object');
const omitBy = require('./_/omit_by');
const nanoid = require('./nanoid');
const { InvalidRequest, InvalidDpopProof } = require('./errors');
const instance = require('./weak_cache');
const resolveResponseMode = require('./resolve_response_mode');

const COOKIES = Symbol('context#cookies');
const UID = Symbol('context#uid');

module.exports = function getContext(provider) {
  const {
    acceptQueryParamAccessTokens,
    clockTolerance,
    features: { dPoP: dPoPConfig, fapiRW: { enabled: fapiEnabled } },
  } = instance(provider).configuration();
  const { app } = provider;

  class OIDCContext extends events.EventEmitter {
    constructor(ctx) {
      super();
      this.ctx = ctx;
      this.route = ctx._matchedRouteName;
      this.authorization = {};
      this.redirectUriCheckPerformed = false;
      this.webMessageUriCheckPerformed = false;
      this.entities = {};
      this.claims = {};
    }

    get uid() {
      if (!this[UID]) {
        this[UID] = (this.ctx.params && this.ctx.params.uid) || nanoid();
      }

      return this[UID];
    }

    set uid(value) {
      this[UID] = value;
    }

    get cookies() {
      if (!this[COOKIES]) {
        this[COOKIES] = app.createContext(this.ctx.req, this.ctx.res).cookies;
        this[COOKIES].secure = !this[COOKIES].secure && this.ctx.secure
          ? true : this[COOKIES].secure;
      }

      return this[COOKIES];
    }

    get issuer() { // eslint-disable-line class-methods-use-this
      return provider.issuer;
    }

    get provider() { // eslint-disable-line class-methods-use-this
      return provider;
    }

    entity(key, value) {
      if (value instanceof provider.BaseToken) {
        ctxRef.set(value, this.ctx);
      }

      this.entities[key] = value;

      if (key === 'Client') {
        this.emit('assign.client', this.ctx, value);
      }
    }

    urlFor(name, opt) {
      const mountPath = (this.ctx.req.originalUrl && this.ctx.req.originalUrl.substring(
        0,
        this.ctx.req.originalUrl.indexOf(this.ctx.request.url),
      ))
        || this.ctx.mountPath // koa-mount
        || this.ctx.req.baseUrl // expressApp.use('/op', provider.callback);
        || ''; // no mount

      return url.resolve(this.ctx.href, provider.pathFor(name, { mountPath, ...opt }));
    }

    promptPending(name) {
      if (this.ctx.oidc.route.endsWith('resume')) {
        const should = new Set([...this.prompts]);
        Object.keys(this.result || {}).forEach(Set.prototype.delete.bind(should));

        return should.has(name);
      }

      // first pass
      return this.prompts.has(name);
    }

    get dPoP() {
      if (!dPoPConfig.enabled) {
        return undefined;
      }

      if ('dpop' in instance(this)) {
        return instance(this).dpop;
      }

      const token = this.ctx.get('DPoP');

      if (!token) {
        return undefined;
      }

      try {
        const { payload, key } = JWT.verify(
          token,
          JWK.EmbeddedJWK,
          {
            maxTokenAge: `${dPoPConfig.iatTolerance} seconds`,
            clockTolerance: `${clockTolerance} seconds`,
            algorithms: instance(provider).configuration('dPoPSigningAlgValues'),
            complete: true,
            typ: 'dpop+jwt',
          },
        );

        if (typeof payload.jti !== 'string' || !payload.jti) {
          throw new Error('must have a jti string property');
        }

        // HTTP Methods are case-insensitive
        if (String(payload.htm).toLowerCase() !== this.ctx.method.toLowerCase()) {
          throw new Error('htm mismatch');
        }

        // TODO: allow trailing slash to be added/omitted at will,
        // see https://github.com/danielfett/draft-dpop/issues/49
        if (payload.htu !== this.urlFor(this.route)) {
          throw new Error('htu mismatch');
        }

        const result = { jwk: key, jti: payload.jti, iat: payload.iat };
        instance(this).dpop = result;

        return result;
      } catch (err) {
        throw new InvalidDpopProof(`invalid DPoP key binding (${err.message})`);
      }
    }

    get requestParamClaims() {
      if ('requestParamClaims' in instance(this)) {
        return instance(this).requestParamClaims;
      }
      const requestParamClaims = new Set();

      if (this.params.claims) {
        const {
          userinfo, id_token: idToken,
        } = JSON.parse(this.params.claims);

        const claims = instance(provider).configuration('claimsSupported');
        if (userinfo) {
          Object.entries(userinfo).forEach(([claim, value]) => {
            if (claims.has(claim) && (value === null || isPlainObject(value))) {
              requestParamClaims.add(claim);
            }
          });
        }

        if (idToken) {
          Object.entries(idToken).forEach(([claim, value]) => {
            if (claims.has(claim) && (value === null || isPlainObject(value))) {
              requestParamClaims.add(claim);
            }
          });
        }
      }

      instance(this).requestParamClaims = requestParamClaims;

      return requestParamClaims;
    }

    get requestParamScopes() {
      if ('requestParamScopes' in instance(this)) {
        return instance(this).requestParamScopes;
      }
      const requestParamScopes = new Set();
      if (this.params.scope) {
        const scopes = this.params.scope.split(' ');
        const { scopes: statics, dynamicScopes: dynamics } = instance(provider).configuration();
        scopes.forEach((scope) => {
          if (statics.has(scope)) {
            requestParamScopes.add(scope);
            return;
          }
          for (const dynamic of dynamics) { // eslint-disable-line no-restricted-syntax
            if (dynamic.test(scope)) {
              requestParamScopes.add(scope);
              return;
            }
          }
        });
      }

      instance(this).requestParamScopes = requestParamScopes;

      return requestParamScopes;
    }

    acceptedScope() {
      // acceptedScopesFor already has the rejected filtered out
      const accepted = this.session.acceptedScopesFor(this.params.client_id);

      return [...this.requestParamScopes].filter((scope) => accepted.has(scope)).join(' ') || undefined;
    }

    resolvedClaims() {
      const rejected = this.session.rejectedClaimsFor(this.params.client_id);
      const claims = JSON.parse(JSON.stringify(this.claims));
      claims.rejected = [...rejected];

      return claims;
    }

    get responseMode() {
      if (typeof this.params.response_mode === 'string') {
        return this.params.response_mode;
      }

      if (this.params.response_type !== undefined) {
        return resolveResponseMode(this.params.response_type);
      }

      return undefined;
    }

    get acr() {
      return this.session.acr;
    }

    get amr() {
      return this.session.amr;
    }

    get prompts() {
      return new Set(this.params.prompt ? this.params.prompt.split(' ') : []);
    }

    get registrationAccessToken() {
      return this.entities.RegistrationAccessToken;
    }

    get deviceCode() {
      return this.entities.DeviceCode;
    }

    get accessToken() {
      return this.entities.AccessToken;
    }

    get account() {
      return this.entities.Account;
    }

    get client() {
      return this.entities.Client;
    }

    getAccessToken({
      acceptDPoP = false, acceptQueryParam = !fapiEnabled && acceptQueryParamAccessTokens,
    } = {}) {
      if ('accessToken' in instance(this)) {
        return instance(this).accessToken;
      }

      const { ctx } = this;
      const mechanisms = omitBy({
        body: get(ctx.oidc, 'body.access_token'),
        header: ctx.headers.authorization,
        query: ctx.query.access_token,
      }, (value) => typeof value !== 'string' || !value);

      debug('uid=%s received access token via %o', this.uid, mechanisms);

      let mechanism;
      let length;
      let token;

      try {
        ({ 0: [mechanism, token], length } = Object.entries(mechanisms));
      } catch (err) {}

      if (!length) {
        throw new InvalidRequest('no access token provided');
      }

      if (length > 1) {
        throw new InvalidRequest('access token must only be provided using one mechanism');
      }

      if (!acceptQueryParam && mechanism === 'query') {
        throw new InvalidRequest('access tokens must not be provided via query parameter');
      }

      let dPoP;
      if (acceptDPoP && dPoPConfig.enabled) {
        ({ dPoP } = this);
      }
      if (mechanism === 'header') {
        const header = token;
        const { 0: scheme, 1: value, length: parts } = header.split(' ');

        if (parts !== 2) {
          throw new InvalidRequest('invalid authorization header value format');
        }

        if (dPoP && scheme.toLowerCase() !== 'dpop') {
          throw new InvalidRequest('authorization header scheme must be `DPoP` when DPoP is used');
        } else if (dPoPConfig.enabled && scheme.toLowerCase() === 'dpop' && !dPoP) {
          throw new InvalidRequest('`DPoP` header not provided');
        } else if (!dPoP && scheme.toLowerCase() !== 'bearer') {
          throw new InvalidRequest('authorization header scheme must be `Bearer`');
        }

        token = value;
      }

      if (dPoP && mechanism !== 'header') {
        throw new InvalidRequest('`DPoP` tokens must be provided via an authorization header');
      }

      instance(this).accessToken = token;

      return token;
    }
  }

  Object.defineProperty(OIDCContext.prototype, 'bearer', {
    get: deprecate(/* istanbul ignore next */ function getBearer() {
      if ('bearer' in instance(this)) {
        return instance(this).bearer;
      }
      const { ctx } = this;
      const mechanisms = omitBy({
        body: get(ctx.oidc, 'body.access_token'),
        header: ctx.headers.authorization,
        query: ctx.query.access_token,
      }, (x) => typeof x === 'undefined');

      debug('uid=%s received bearer via %o', this.uid, mechanisms);

      let mechanism;
      let length;
      let bearer;

      try {
        ({ 0: [mechanism, bearer], length } = Object.entries(mechanisms));
      } catch (err) {}

      if (!length) {
        throw new InvalidRequest('no bearer auth mechanism provided');
      }

      if (length > 1) {
        throw new InvalidRequest('bearer token must only be provided using one mechanism');
      }

      if (mechanism === 'header') {
        const header = bearer;
        const { 0: scheme, 1: value, length: parts } = header.split(' ');

        if (parts !== 2 || scheme.toLowerCase() !== 'bearer') {
          throw new InvalidRequest('invalid authorization header value format');
        }

        bearer = value;
      }

      if (!bearer) {
        throw new InvalidRequest('no bearer token provided');
      }

      instance(this).bearer = bearer;
      return bearer;
    }, 'ctx.oidc.bearer is deprecated, use ctx.oidc.getAccessToken() instead'),
  });

  return OIDCContext;
};
