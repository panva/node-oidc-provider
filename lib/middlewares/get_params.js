'use strict';

const _ = require('lodash');

module.exports = function getParams(options) {
  const opts = options || {};
  opts.whitelist = 'whitelist' in opts ? opts.whitelist : [];

  return function * assembleParams(next) {
    const params = this.method === 'POST' ? this.request.body : this.query;
    this.oidc.params = _.pick(params, opts.whitelist);
    yield next;
  };
};
