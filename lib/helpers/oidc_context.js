const events = require('events');
const url = require('url');
const { deprecate } = require('util');

const isPlainObject = require('lodash/isPlainObject');
const cloneDeep = require('lodash/cloneDeep');
const omitBy = require('lodash/omitBy');
const get = require('lodash/get');
const isUndefined = require('lodash/isUndefined');
const debug = require('debug')('oidc-provider:bearer');
const { JWT, JWK, errors } = require('@panva/jose');

const ctxRef = require('../models/ctx_ref');

const nanoid = require('./nanoid');
const { InvalidRequest } = require('./errors');
const instance = require('./weak_cache');
const resolveResponseMode = require('./resolve_response_mode');

module.exports = function getContext(provider) {
  const { clockTolerance, features: { dPoP: dPoPConfig } } = instance(provider).configuration();
  const { app } = provider;

  class OIDCContext extends events.EventEmitter {
    constructor(ctx) {
      super();
      this.ctx = ctx;
      this.route = ctx._matchedRouteName;
      this.authorization = {};
      this.redirectUriCheckPerformed = false;
      this.webMessageUriCheckPerformed = false;
      this.uid = (ctx.params && ctx.params.uid) || nanoid();
      this.entities = {};
      this.claims = {};
      this.cookies = app.createContext(ctx.req, ctx.res).cookies;
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

      this.emit(`assign.${key.toLowerCase()}`, this.ctx, value);
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
        const { header, payload } = JWT.decode(token, { complete: true });
        let key;

        if (header.typ !== 'dpop+jwt') {
          throw new Error('typ must be dpop+jwt');
        }
        if (typeof header.alg !== 'string' || !header.alg || header.alg === 'none' || header.alg.startsWith('HS')) {
          throw new Error('invalid alg');
        }
        if (!instance(provider).configuration('dPoPSigningAlgValues').includes(header.alg)) {
          throw new Error('unsupported alg');
        }
        if (typeof header.jwk !== 'object' || !header.jwk) {
          throw new Error('header must have a jwk');
        }
        try {
          key = JWK.asKey(header.jwk);
        } catch (err) {
          throw new Error('failed to import jwk');
        }
        if (key.type !== 'public') {
          throw new Error('jwk must be a public key');
        }
        if (typeof payload.jti !== 'string' || !payload.jti) {
          throw new Error('must have a jti string property');
        }
        if (typeof payload.iat !== 'number' || !payload.iat) {
          throw new Error('must have a iat number property');
        }
        if (payload.http_method !== this.ctx.method) {
          throw new Error('http_method mismatch');
        }
        if (payload.http_uri !== `${this.ctx.origin}${this.ctx.path}`) {
          throw new Error('http_uri mismatch');
        }

        try {
          JWT.verify(token, key, { maxTokenAge: `${dPoPConfig.iatTolerance} seconds`, clockTolerance: `${clockTolerance} seconds` });
        } catch (err) {
          if (err instanceof errors.JWTClaimInvalid) {
            throw new Error(`failed claim check (${err.message})`);
          }
          throw err;
        }

        const result = { jwk: key, jti: payload.jti, iat: payload.iat };
        instance(this).dpop = result;
        return result;
      } catch (err) {
        throw new InvalidRequest(`invalid DPoP Proof JWT (${err.message})`);
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
      const claims = cloneDeep(this.claims);
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

    getAccessToken({ acceptDPoP = false, acceptQueryParam = true } = {}) {
      if ('accessToken' in instance(this)) {
        return instance(this).accessToken;
      }
      const { ctx } = this;
      const mechanisms = omitBy({
        body: get(ctx.oidc, 'body.access_token'),
        header: ctx.headers.authorization,
        query: acceptQueryParam ? ctx.query.access_token : undefined,
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
      }, isUndefined);

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
