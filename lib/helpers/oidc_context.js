const _ = require('lodash');
const url = require('url');
const uuid = require('uuid/v4');
const debug = require('debug')('oidc-provider:bearer');

const { InvalidRequest } = require('./errors');

module.exports = function getContext(provider) {
  const map = new WeakMap();

  function instance(ctx) {
    if (!map.has(ctx)) map.set(ctx, { claims: {} });
    return map.get(ctx);
  }

  class OIDCContext {
    constructor(ctx) {
      this.ctx = ctx;
      this.authorization = {};
      this.redirectUriCheckPerformed = false;
      this.uuid = uuid();
      this.entities = {};
    }

    entity(key, value) {
      this.entities[key] = value;
    }

    urlFor(name, opt) {
      const mountPath = (this.ctx.req.originalUrl && this.ctx.req.originalUrl.substring(
        0,
        this.ctx.req.originalUrl.indexOf(this.ctx.request.url),
      )) ||
        this.ctx.mountPath || // koa-mount
        this.ctx.req.baseUrl || // expressApp.use('/op', provider.callback);
        ''; // no mount

      return url.resolve(this.ctx.href, provider.pathFor(name, { mountPath, ...opt }));
    }

    promptPending(name) {
      if (this.ctx._matchedRouteName === 'authorization') { // first pass
        return this.prompts && this.prompts.includes(name);
      }

      // result pass
      if (name === 'none') return true;

      const should = _.difference(this.prompts, Object.keys(this.result || {}));
      return should.includes(name);
    }

    get acr() {
      return _.get(this, 'result.login.acr');
    }

    get amr() {
      return _.get(this, 'result.login.amr');
    }

    set claims(value) { instance(this).claims = value; }

    get prompts() { return this.params.prompt ? this.params.prompt.split(' ') : []; }
    get claims() { return instance(this).claims; }
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

      debug('uuid=%s received bearer via %o', this.uuid, mechanisms);

      const { length } = Object.keys(mechanisms);

      if (!length) throw new InvalidRequest('no bearer token provided');

      if (length > 1) {
        throw new InvalidRequest('bearer token must only be provided using one mechanism');
      }

      let bearer;
      _.forEach(mechanisms, (value, mechanism) => {
        if (mechanism === 'header') {
          const parts = value.split(' ');

          if (parts.length !== 2 || parts[0] !== 'Bearer') {
            throw new InvalidRequest('invalid authorization header value format');
          }

          bearer = parts[1]; // eslint-disable-line prefer-destructuring
        } else {
          bearer = value;
        }
      });

      if (!bearer) throw new InvalidRequest('no bearer token provided');

      instance(this).bearer = bearer;
      return bearer;
    }

    get registrationAccessToken() {
      return this.entities.RegistrationAccessToken;
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
