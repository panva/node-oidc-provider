'use strict';

const _ = require('lodash');
const url = require('url');
const uuid = require('uuid').v4;

const errors = require('./errors');

module.exports = function getContext(provider) {
  const map = new WeakMap();

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
      const mountPath = (this.ctx.req.originalUrl && this.ctx.req.originalUrl.substring(0,
        this.ctx.req.originalUrl.indexOf(this.ctx.request.url))) || this.ctx.mountPath || '';

      return url.resolve(this.ctx.href, provider.pathFor(name, Object.assign({ mountPath }, opt)));
    }

    prompted(name) {
      if (!this.result) {
        return this.prompts && this.prompts.indexOf(name) !== -1;
      }

      if (name === 'none') return true;

      const should = _.difference(this.prompts, _.keys(this.result));
      return should.indexOf(name) !== -1;
    }

    set params(value) { Object.defineProperty(this, 'params', { enumerable: true, value }); }
    set account(value) { Object.defineProperty(this, 'account', { value }); }
    set client(value) { Object.defineProperty(this, 'client', { value }); }
    set claims(value) { instance(this).claims = value; }

    get prompts() { return this.params.prompt ? this.params.prompt.split(' ') : []; }
    get claims() { return instance(this).claims; }
    get bearer() {
      const ctx = this.ctx;
      const mechanisms = _.omitBy({
        body: _.get(ctx.request, 'body.access_token'),
        header: ctx.headers.authorization,
        query: ctx.query.access_token,
      }, _.isUndefined);

      const length = Object.keys(mechanisms).length;

      if (!length) {
        throw new errors.InvalidRequestError('no bearer token provided');
      }
      if (length > 1) {
        throw new errors.InvalidRequestError(
          'bearer token must only be provided using one mechanism');
      }

      let bearer;
      _.forEach(mechanisms, (value, mechanism) => {
        if (mechanism === 'header') {
          const parts = value.split(' ');

          if (parts.length !== 2 || parts[0] !== 'Bearer') {
            throw new errors.InvalidRequestError('invalid authorization header value format');
          }

          bearer = parts[1];
        } else {
          bearer = value;
        }
      });

      if (!bearer) throw new errors.InvalidRequestError('no bearer token provided');

      return bearer;
    }
  }

  return OIDCContext;
};
