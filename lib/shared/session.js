const instance = require('../helpers/weak_cache');
const ssHandler = require('../helpers/samesite_handler');

module.exports = async function sessionHandler(ctx, next) {
  ctx.oidc.session = new Proxy(await ctx.oidc.provider.Session.get(ctx), {
    set(obj, prop, value) {
      switch (prop) {
        case 'touched':
          Reflect.defineProperty(obj, 'touched', { writable: true, value });
          break;
        case 'destroyed':
          Reflect.defineProperty(obj, 'destroyed', { configurable: false, writable: true, value });
          Reflect.defineProperty(obj, 'touched', { configurable: false, writable: false, value: false });
          break;
        case 'account':
          if (typeof value !== 'string' || !value) {
            throw new TypeError(`account must be a non-empty string, got: ${typeof value}`);
          }
        default: // eslint-disable-line no-fallthrough
          Reflect.set(obj, prop, value);
          Reflect.defineProperty(obj, 'touched', { writable: true, value: true });
      }

      return true;
    },
  });

  try {
    await next();
  } finally {
    const sessionCookieName = ctx.oidc.provider.cookieName('session');
    const stateCookieName = ctx.oidc.provider.cookieName('state');
    const longRegexp = new RegExp(`^(${sessionCookieName}|${stateCookieName}\\.[^=]+)(?:\\.legacy)?(?:\\.sig)?=`);

    // refresh the session duration
    if ((!ctx.oidc.session.new || ctx.oidc.session.touched) && !ctx.oidc.session.destroyed) {
      ssHandler.set(
        ctx.oidc.cookies,
        sessionCookieName,
        ctx.oidc.session.id,
        instance(ctx.oidc.provider).configuration('cookies.long'),
      );
      await ctx.oidc.session.save();
    }

    if (ctx.response.get('set-cookie')) {
      ctx.response.get('set-cookie').forEach((cookie, index, ary) => {
        /* eslint-disable no-param-reassign */
        if (ctx.oidc.session.transient && cookie.includes('expires=') && !cookie.includes('expires=Thu, 01 Jan 1970') && cookie.match(longRegexp)) {
          ary[index] = cookie.replace(/(; ?expires=([\w\d:, ]+))/, '');
        }
        /* eslint-enable */
      });
    }
  }
};
