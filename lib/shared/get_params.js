'use strict';

const assert = require('assert');

module.exports = function getParams(whitelist) {
  assert(whitelist, 'whitelist must be present');

  class Params {
    constructor(params) {
      whitelist.forEach((prop) => { this[prop] = params[prop]; });
      Object.seal(this);
    }
  }

  return async function assembleParams(ctx, next) {
    const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
    ctx.oidc.params = new Params(params);
    await next();
  };
};
