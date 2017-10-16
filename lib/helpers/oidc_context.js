const _ = require('lodash');
const url = require('url');
const uuid = require('uuid/v4');
const debug = require('debug')('oidc-provider:bearer');

const { InvalidRequestError } = require('./errors');
const providerInstance = require('../helpers/weak_cache');

module.exports = function getContext(provider) {
  const map = new WeakMap();
  const acrValues = providerInstance(provider).configuration('acrValues');

  function instance(ctx) {
    if (!map.has(ctx)) map.set(ctx, { claims: {} });
    return map.get(ctx);
  }

  class OIDCContext {
    constructor(ctx) {
      Object.defineProperty(this, 'ctx', { value: ctx });
      Object.defineProperty(this, 'authorization', { writable: true });
      Object.defineProperty(this, 'redirectUriCheckPerformed', { writable: true });
      this.uuid = uuid();
    }

    urlFor(name, opt) {
      const mountPath = (this.ctx.req.originalUrl && this.ctx.req.originalUrl.substring(
        0,
        this.ctx.req.originalUrl.indexOf(this.ctx.request.url),
      )) ||
        this.ctx.mountPath || // koa-mount
        this.ctx.req.baseUrl || // expressApp.use('/op', provider.callback);
        ''; // no mount

      return url.resolve(this.ctx.href, provider.pathFor(name, Object.assign({ mountPath }, opt)));
    }

    promptPending(name) {
      if (!this.result) { // first pass
        return this.prompts && this.prompts.includes(name);
      }

      // result pass
      if (name === 'none') return true;

      const should = _.difference(this.prompts, Object.keys(this.result));
      return should.includes(name);
    }

    get acr() {
      return _.get(this, 'result.login.acr', acrValues[0]);
    }

    get amr() {
      return _.get(this, 'result.login.amr', undefined);
    }

    set body(value) { Object.defineProperty(this, 'body', { enumerable: true, value }); }
    set params(value) { Object.defineProperty(this, 'params', { enumerable: true, value }); }
    set signed(value) { Object.defineProperty(this, 'signed', { enumerable: true, value }); }
    set account(value) { Object.defineProperty(this, 'account', { value }); }
    set client(value) { Object.defineProperty(this, 'client', { value }); }
    set claims(value) { instance(this).claims = value; }

    get prompts() { return this.params.prompt ? this.params.prompt.split(' ') : []; }
    get claims() { return instance(this).claims; }
    get bearer() {
      const { ctx } = this;
      const mechanisms = _.omitBy({
        body: _.get(ctx.oidc, 'body.access_token'),
        header: ctx.headers.authorization,
        query: ctx.query.access_token,
      }, _.isUndefined);

      debug('uuid=%s received bearer via %o', this.uuid, mechanisms);

      const { length } = Object.keys(mechanisms);

      if (!length) throw new InvalidRequestError('no bearer token provided');

      if (length > 1) {
        throw new InvalidRequestError('bearer token must only be provided using one mechanism');
      }

      let bearer;
      _.forEach(mechanisms, (value, mechanism) => {
        if (mechanism === 'header') {
          const parts = value.split(' ');

          if (parts.length !== 2 || parts[0] !== 'Bearer') {
            throw new InvalidRequestError('invalid authorization header value format');
          }

          bearer = parts[1]; // eslint-disable-line prefer-destructuring
        } else {
          bearer = value;
        }
      });

      if (!bearer) throw new InvalidRequestError('no bearer token provided');

      return bearer;
    }
  }

  return OIDCContext;
};
