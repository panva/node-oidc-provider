module.exports = function getSessionHandler(provider) {
  return async function sessionHandler(ctx, next) {
    ctx.oidc.session = new Proxy(await provider.Session.get(ctx), {
      set(obj, prop, value) {
        if (prop === 'touched') {
          Reflect.defineProperty(obj, 'touched', { writable: true, value });
        } else if (prop === 'destroyed') {
          Reflect.defineProperty(obj, 'destroyed', { writable: true, value });
          Reflect.defineProperty(obj, 'touched', { writable: true, value: false });
        } else {
          Reflect.set(obj, prop, value);
          Reflect.defineProperty(obj, 'touched', { writable: true, value: true });
        }
        return true;
      },
    });

    try {
      await next();
    } catch (err) {
      throw err;
    } finally {
      if (ctx.oidc.session.transient) {
        const sessionCookieName = provider.cookieName('session');
        const stateCookieName = provider.cookieName('state');

        ctx.response.get('set-cookie').forEach((cookie, index, ary) => {
          const isLong = cookie.startsWith(sessionCookieName) || cookie.startsWith(stateCookieName);
          if (isLong && !cookie.includes('expires=Thu, 01 Jan 1970')) {
            ary[index] = cookie.replace(/(; ?expires=([\w\d:, ]+))/, ''); // eslint-disable-line no-param-reassign
          }
        });
      }

      if (!ctx.oidc.session.destroyed) await ctx.oidc.session.save();
    }
  };
};
