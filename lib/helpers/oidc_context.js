import * as events from 'node:events';
import * as url from 'node:url';

import ctxRef from '../models/ctx_ref.js';

import get from './_/get.js';
import isPlainObject from './_/is_plain_object.js';
import omitBy from './_/omit_by.js';
import { InvalidRequest } from './errors.js';
import instance from './weak_cache.js';
import resolveResponseMode from './resolve_response_mode.js';

const COOKIES = Symbol();

export default function getContext(provider) {
  const {
    acceptQueryParamAccessTokens,
    features: {
      dPoP: dPoPConfig,
      fapi,
    },
    scopes: oidcScopes,
  } = instance(provider).configuration();
  const { app } = provider;

  class OIDCContext extends events.EventEmitter {
    #requestParamClaims = null;

    #accessToken = null;

    #fapiProfile = null;

    constructor(ctx) {
      super();
      this.ctx = ctx;
      this.route = ctx._matchedRouteName;
      this.authorization = {};
      this.redirectUriCheckPerformed = false;
      this.webMessageUriCheckPerformed = false;
      this.entities = {};
      this.claims = {};
      this.resourceServers = {};
    }

    get cookies() {
      if (!this[COOKIES]) {
        this[COOKIES] = app.createContext(this.ctx.req, this.ctx.res).cookies;
        this[COOKIES].secure = !this[COOKIES].secure && this.ctx.secure
          ? true : this[COOKIES].secure;
      }

      return this[COOKIES];
    }

    get fapiProfile() {
      if (this.#fapiProfile === null) {
        this.#fapiProfile = fapi.profile(this.ctx, this.client);
      }

      return this.#fapiProfile;
    }

    isFapi(...oneOf) {
      const i = oneOf.indexOf(this.fapiProfile);
      return i !== -1 ? oneOf[i] : undefined;
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
        || this.ctx.req.baseUrl // expressApp.use('/op', provider.callback());
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

    get requestParamClaims() {
      if (this.#requestParamClaims) {
        return this.#requestParamClaims;
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

      this.#requestParamClaims = requestParamClaims;

      return requestParamClaims;
    }

    clientJwtAuthExpectedAudience() {
      return new Set([this.issuer, this.urlFor('token'), this.urlFor(this.route)]);
    }

    get requestParamScopes() {
      return new Set(this.params.scope ? this.params.scope.split(' ') : undefined);
    }

    get requestParamOIDCScopes() {
      if (!this.params.scope) {
        return new Set();
      }

      return new Set(this.params.scope.split(' ').filter(Set.prototype.has.bind(oidcScopes)));
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

    get grant() {
      return this.entities.Grant;
    }

    getAccessToken({
      acceptDPoP = false, acceptQueryParam = acceptQueryParamAccessTokens && !fapi.enabled,
    } = {}) {
      if (this.#accessToken) {
        return this.#accessToken;
      }

      const { ctx } = this;
      const mechanisms = omitBy({
        body: ctx.is('application/x-www-form-urlencoded') && get(ctx.oidc, 'body.access_token'),
        header: ctx.headers.authorization,
        query: ctx.query.access_token,
      }, (value) => typeof value !== 'string' || !value);

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

      const dpop = acceptDPoP && dPoPConfig.enabled && ctx.get('DPoP');

      if (mechanism === 'header') {
        const header = token;
        const { 0: scheme, 1: value, length: parts } = header.split(' ');

        if (parts !== 2) {
          throw new InvalidRequest('invalid authorization header value format');
        }

        if (dpop && scheme.toLowerCase() !== 'dpop') {
          throw new InvalidRequest('authorization header scheme must be `DPoP` when DPoP is used');
        } else if (!dpop && scheme.toLowerCase() === 'dpop') {
          throw new InvalidRequest('`DPoP` header not provided');
        } else if (!dpop && scheme.toLowerCase() !== 'bearer') {
          throw new InvalidRequest('authorization header scheme must be `Bearer`');
        }

        token = value;
      }

      if (dpop && mechanism !== 'header') {
        throw new InvalidRequest('`DPoP` tokens must be provided via an authorization header');
      }

      this.#accessToken = token;

      return token;
    }
  }

  return OIDCContext;
}
