'use strict';

const assert = require('assert');
const bodyMw = require('koa-body');
const errors = require('../helpers/errors');

module.exports = function getSelectiveBody(only) {
  assert(only, 'only must be provided');
  const bodyParser = bodyMw({ jsonLimit: '56kb', formLimit: '56kb' });

  return async function selectiveBody(ctx, next) {
    if (ctx.is(only)) {
      await bodyParser(ctx, next);
    } else {
      const msg = `only ${only} content-type ${ctx.method} bodies are supported`;
      ctx.throw(new errors.InvalidRequestError(msg));
    }
  };
};
