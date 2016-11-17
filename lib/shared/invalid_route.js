'use strict';

const errors = require('../helpers/errors');

module.exports = async function invalidRoute(ctx, next) {
  await next();
  if (ctx.status === 404 && ctx.message === 'Not Found') {
    ctx.throw(new errors.InvalidRequestError('unrecognized route', 404));
  }
};
