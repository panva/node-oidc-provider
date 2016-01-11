'use strict';

let bodyMw = require('koa-body');
let errors = require('../helpers/errors');

module.exports = function (opts) {
  opts = opts || {};
  opts.patchNode = 'patchNode' in opts ? opts.patchNode : false;
  opts.patchKoa = 'patchKoa' in opts ? opts.patchKoa : true;
  opts.only = 'only' in opts ?
    opts.only : ['application/x-www-form-urlencoded'];
  opts.raise = 'raise' in opts ? opts.raise : false;

  let bodyParser = bodyMw(opts);
  return function * selectiveBody(next) {
    if (this.is(opts.only)) {
      yield bodyParser.call(this, next);
    } else if (opts.raise) {
      let msg = 'only ' + opts.only + ' content-type POST bodies are supported';
      this.throw(new errors.InvalidRequestError(msg));
    } else {
      let body = {};
      if (opts.patchNode) {
        this.req.body = body;
      }
      if (opts.patchKoa) {
        this.request.body = body;
      }
      yield next;
    }
  };
};
