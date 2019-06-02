const url = require('url');
const events = require('events');

const _ = require('lodash');
const debug = require('debug')('oidc-provider:bearer');

const ctxRef = require('../models/ctx_ref');

const nanoid = require('./nanoid');
const { InvalidRequest } = require('./errors');
const instance = require('./weak_cache');

module.exports = function getContext(provider) {
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
            if (claims.has(claim) && (value === null || _.isPlainObject(value))) {
              requestParamClaims.add(claim);
            }
          });
        }

        if (idToken) {
          Object.entries(idToken).forEach(([claim, value]) => {
            if (claims.has(claim) && (value === null || _.isPlainObject(value))) {
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

      return [...this.requestParamScopes].filter(scope => accepted.has(scope)).join(' ') || undefined;
    }

    resolvedClaims() {
      const rejected = this.session.rejectedClaimsFor(this.params.client_id);
      const claims = _.cloneDeep(this.claims);
      claims.rejected = [...rejected];

      return claims;
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

    get bearer() {
      if ('bearer' in instance(this)) {
        return instance(this).bearer;
      }
      const { ctx } = this;
      const mechanisms = _.omitBy({
        body: _.get(ctx.oidc, 'body.access_token'),
        header: ctx.headers.authorization,
        query: ctx.query.access_token,
      }, _.isUndefined);

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

        if (parts !== 2 || scheme !== 'Bearer') {
          throw new InvalidRequest('invalid authorization header value format');
        }

        bearer = value;
      }

      if (!bearer) {
        throw new InvalidRequest('no bearer token provided');
      }

      instance(this).bearer = bearer;
      return bearer;
    }

    get registrationAccessToken() {
      return this.entities.RegistrationAccessToken;
    }

    get deviceCode() {
      return this.entities.DeviceCode;
    }

    get account() {
      return this.entities.Account;
    }

    get client() {
      return this.entities.Client;
    }
  }

  return OIDCContext;
};
