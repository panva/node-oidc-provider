module.exports = async function noCache(ctx, next) {
  ctx.set('cache-control', 'no-store');
  await next();
};
