'use strict';

let _ = require('lodash');

module.exports = function(opts) {
  opts = opts || {};
  opts.whitelist = 'whitelist' in opts ? opts.whitelist : [];

  return function * getParams(next) {
    let params = this.method === 'POST' ? this.request.body : this.query;

    this.oidc.params = _.pick(params, opts.whitelist);

    yield next;
  };
};
