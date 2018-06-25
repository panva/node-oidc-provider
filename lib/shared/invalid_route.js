const { InvalidRequest } = require('../helpers/errors');

module.exports = async function invalidRoute(ctx, next) {
  await next();
  if (ctx.status === 404 && ctx.message === 'Not Found') {
    throw new InvalidRequest('unrecognized route', 404);
  }
};
