module.exports = async function noCache(ctx, next) {
  ctx.set('Pragma', 'no-cache');
  ctx.set('Cache-Control', 'no-cache, no-store');
  await next();
};
