const instance = require('../helpers/weak_cache');

module.exports = function getSessionHandler(provider) {
  return async function sessionHandler(ctx, next) {
    ctx.oidc.session = new Proxy(await provider.Session.get(ctx), {
      set(obj, prop, value) {
        if (prop === 'touched') {
          Reflect.defineProperty(obj, 'touched', { writable: true, value });
        } else if (prop === 'destroyed') {
          Reflect.defineProperty(obj, 'destroyed', { configurable: false, writable: true, value });
          Reflect.defineProperty(obj, 'touched', { configurable: false, writable: false, value: false });
        } else {
          Reflect.set(obj, prop, value);
          Reflect.defineProperty(obj, 'touched', { writable: true, value: true });
        }
        return true;
      },
    });

    try {
      await next();
    } finally {
      const sessionCookieName = provider.cookieName('session');

      // refresh the session duration
      if ((!ctx.oidc.session.new || ctx.oidc.session.touched) && !ctx.oidc.session.destroyed) {
        ctx.cookies.set(sessionCookieName, ctx.oidc.session.id, instance(provider).configuration('cookies.long'));
        await ctx.oidc.session.save();
      }

      if (ctx.oidc.session.transient) {
        const stateCookieName = provider.cookieName('state');

        ctx.response.get('set-cookie').forEach((cookie, index, ary) => {
          const isLong = cookie.startsWith(sessionCookieName) || cookie.startsWith(stateCookieName);
          if (isLong && !cookie.includes('expires=Thu, 01 Jan 1970')) {
            ary[index] = cookie.replace(/(; ?expires=([\w\d:, ]+))/, ''); // eslint-disable-line no-param-reassign
          }
        });
      }
    }
  };
};
