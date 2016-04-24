'use strict';

const bodyMw = require('koa-body');
const errors = require('../helpers/errors');

module.exports = function getSelectiveBody(options) {
  const opts = options || {};
  opts.patchNode = 'patchNode' in opts ? opts.patchNode : false;
  opts.patchKoa = 'patchKoa' in opts ? opts.patchKoa : true;
  opts.only = 'only' in opts ?
    opts.only : ['application/x-www-form-urlencoded'];
  opts.raise = 'raise' in opts ? opts.raise : false;

  const bodyParser = bodyMw(opts);
  return function * selectiveBody(next) {
    if (this.is(opts.only)) {
      yield bodyParser.call(this, next);
    } else if (opts.raise) {
      const msg = `only ${opts.only} content-type POST bodies are supported`;
      this.throw(new errors.InvalidRequestError(msg));
    } else {
      const body = {};

      if (opts.patchNode) this.req.body = body;
      if (opts.patchKoa) this.request.body = body;

      yield next;
    }
  };
};
