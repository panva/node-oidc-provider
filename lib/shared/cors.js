const cors = require('@koa/cors');

module.exports = (opts) => {
  const builtin = cors(opts);

  return (ctx, next) => {
    const headers = Object.keys(ctx.response.headers);

    if (headers.find(x => x.toLowerCase().startsWith('access-control-'))) {
      return next();
    }

    return builtin(ctx, next);
  };
};
