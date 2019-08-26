const { ENGINE_MAP: { WebKit: webkitEngineName }, getParser: Parser } = require('bowser');

const instance = require('../helpers/weak_cache');

module.exports = async function sessionHandler(ctx, next) {
  ctx.oidc.session = new Proxy(await ctx.oidc.provider.Session.get(ctx), {
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
    const sessionCookieName = ctx.oidc.provider.cookieName('session');
    const stateCookieName = ctx.oidc.provider.cookieName('state');
    const longRegexp = new RegExp(`^(${sessionCookieName}|${stateCookieName}\\.[^=]+)(?:\\.sig)?=`);

    // refresh the session duration
    if ((!ctx.oidc.session.new || ctx.oidc.session.touched) && !ctx.oidc.session.destroyed) {
      ctx.oidc.cookies.set(sessionCookieName, ctx.oidc.session.id, instance(ctx.oidc.provider).configuration('cookies.long'));
      await ctx.oidc.session.save();
    }

    let isWebKit = false;
    const ua = ctx.get('user-agent');
    if (ua) {
      const parser = new Parser(ua, false);
      isWebKit = parser.getEngineName() === webkitEngineName;
    }

    if (ctx.response.get('set-cookie')) {
      ctx.response.get('set-cookie').forEach((cookie, index, ary) => {
        /* eslint-disable no-param-reassign, no-multi-assign */
        // TODO: remove when https://github.com/pillarjs/cookies/issues/109 lands
        if (!cookie.includes('samesite=')) {
          ary[index] = cookie = `${cookie}; samesite=none`;
        }

        // WebKit treats unrecognized (yet) "None" value as "Strict" instead
        // https://bugs.webkit.org/show_bug.cgi?id=198181
        // TODO: remove when no longer needed
        if (isWebKit && cookie.includes('; samesite=none')) {
          ary[index] = cookie = cookie.replace('; samesite=none', '');
        }

        if (ctx.oidc.session.transient && cookie.includes('expires=') && !cookie.includes('expires=Thu, 01 Jan 1970') && cookie.match(longRegexp)) {
          ary[index] = cookie.replace(/(; ?expires=([\w\d:, ]+))/, '');
        }
        /* eslint-enable */
      });
    }
  }
};
