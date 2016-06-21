'use strict';

const _ = require('lodash');
const assert = require('assert');

module.exports = function getParams(whitelist) {
  assert.ok(whitelist, 'whitelist must be present');

  return function * assembleParams(next) {
    const params = this.method === 'POST' ? this.request.body : this.query;
    this.oidc.params = _.pick(params, whitelist);
    yield next;
  };
};
