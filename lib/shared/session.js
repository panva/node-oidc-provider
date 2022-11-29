import instance from '../helpers/weak_cache.js';
import * as ssHandler from '../helpers/samesite_handler.js';

export default async function sessionHandler(ctx, next) {
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
        case 'accountId':
          if (typeof value !== 'string' || !value) {
            throw new TypeError(`accountId must be a non-empty string, got: ${typeof value}`);
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
    const longRegExp = new RegExp(`^${sessionCookieName}(?:\\.legacy)?(?:\\.sig)?=`);

    // refresh the session duration
    if ((!ctx.oidc.session.new || ctx.oidc.session.touched) && !ctx.oidc.session.destroyed) {
      let ttl = instance(ctx.oidc.provider).configuration('ttl.Session');

      if (typeof ttl === 'function') {
        ttl = ttl(ctx, ctx.oidc.session);
      }

      ssHandler.set(
        ctx.oidc.cookies,
        sessionCookieName,
        ctx.oidc.session.id,
        instance(ctx.oidc.provider).configuration('cookies.long'),
      );
      await ctx.oidc.session.save(ttl);
    }

    if (ctx.response.get('set-cookie')) {
      ctx.response.get('set-cookie').forEach((cookie, index, ary) => {
        /* eslint-disable no-param-reassign */
        if (
          !cookie.includes('expires=Thu, 01 Jan 1970')
          && cookie.match(longRegExp)
          && !ctx.oidc.session.transient
          && ctx.oidc.session.exp
        ) {
          ary[index] += `; expires=${new Date(ctx.oidc.session.exp * 1000).toUTCString()}`;
        }
        /* eslint-enable */
      });
    }
  }
}
