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

  return function* assembleParams(next) {
    const params = this.method === 'POST' ? this.request.body : this.query;
    this.oidc.params = new Params(params);
    yield next;
  };
};
