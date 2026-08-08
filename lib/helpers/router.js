import * as querystring from 'node:querystring';

/*
 * The router @koa/router was providing here, limited to what this application
 * registers: five verbs, named routes, a single trailing `:param` segment on a
 * handful of paths, reverse lookup for Provider#pathFor, and nothing else - no
 * prefixes, no nesting, no allowedMethods, no regular expression paths, no
 * optional or repeating segments.
 *
 * Paths are matched by segment comparison rather than by compiling them to
 * regular expressions, which is what keeps this both smaller and faster than
 * @koa/router plus path-to-regexp.
 *
 * path-to-regexp matches case insensitively and tolerates one trailing slash by
 * default, so POST /TOKEN and POST /token/ both reach the token endpoint today.
 * That is reproduced here rather than tightened: it is the behaviour every
 * deployment currently has, and narrowing it is a decision to make on its own
 * rather than as a side effect of dropping a dependency.
 *
 * A method that matches no route falls through to koa's 404 - the same as
 * before, since allowedMethods was never mounted, so there is no 405 or Allow
 * header to reproduce.
 *
 * test/router/router_parity.test.js holds this to @koa/router itself.
 */

// koa-compose
function compose(middleware) {
  return function composed(ctx, next) {
    let index = -1;
    function dispatch(i) {
      if (i <= index) return Promise.reject(new Error('next() called multiple times'));
      index = i;
      const fn = i === middleware.length ? next : middleware[i];
      if (!fn) return Promise.resolve();
      try {
        return Promise.resolve(fn(ctx, dispatch.bind(null, i + 1)));
      } catch (err) {
        return Promise.reject(err);
      }
    }
    return dispatch(0);
  };
}

function decode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/*
 * Case folding as a case-insensitive RegExp without the `u` flag does it, which
 * is what path-to-regexp compiled paths to. toLowerCase() is not the same: it
 * folds U+212A KELVIN SIGN to `k`, so /toKen would reach the token endpoint
 * while the regex - and therefore anything in front of the provider matching on
 * the literal path - would not. That rule is the last clause below: a
 * non-ASCII character whose uppercase is ASCII stays as it is.
 */
function fold(value) {
  for (let i = 0; i < value.length; i += 1) {
    if (value.charCodeAt(i) > 127) {
      let out = '';
      for (const char of value) {
        const upper = char.toUpperCase();
        out += upper.length === 1 && !(char.codePointAt(0) > 127 && upper.codePointAt(0) < 128)
          ? upper
          : char;
      }
      return out;
    }
  }
  return value.toUpperCase();
}

export default class Router {
  #static = new Map();

  #dynamic = [];

  #names = new Map();

  #register(method, name, path, middleware) {
    // first registration wins, matching @koa/router's reverse lookup: `discovery`
    // is registered for both well-known paths and resolves to the first
    if (!this.#names.has(name)) this.#names.set(name, path);

    const route = { name, path, run: compose(middleware) };
    // @koa/router routes HEAD to GET handlers
    const methods = method === 'GET' ? ['GET', 'HEAD'] : [method];

    if (!path.includes('/:')) {
      const key = fold(path);
      let byMethod = this.#static.get(key);
      if (!byMethod) {
        byMethod = new Map();
        this.#static.set(key, byMethod);
      }
      for (const verb of methods) if (!byMethod.has(verb)) byMethod.set(verb, route);
      return;
    }

    const raw = path.split('/');
    // null marks a `:param` slot; `keys` keeps its original spelling, since the
    // segments themselves are folded for case insensitive comparison
    const segments = raw.map((s) => (s.charCodeAt(0) === 0x3a ? null : fold(s)));
    const keys = raw.map((s) => (s.charCodeAt(0) === 0x3a ? s.slice(1) : null));
    for (const verb of methods) this.#dynamic.push({ verb, segments, keys, route });
  }

  get(name, path, ...middleware) { this.#register('GET', name, path, middleware); return this; }

  post(name, path, ...middleware) { this.#register('POST', name, path, middleware); return this; }

  put(name, path, ...middleware) { this.#register('PUT', name, path, middleware); return this; }

  delete(name, path, ...middleware) { this.#register('DELETE', name, path, middleware); return this; }

  options(name, path, ...middleware) { this.#register('OPTIONS', name, path, middleware); return this; }

  #lookup(method, path) {
    const folded = fold(path);

    const route = this.#static.get(folded)?.get(method);
    if (route) return { route, params: {} };

    if (this.#dynamic.length) {
      // params keep the request's own casing, comparison does not
      const parts = path.split('/');
      const foldedParts = folded.split('/');

      for (const candidate of this.#dynamic) {
        if (candidate.verb !== method || candidate.segments.length !== parts.length) continue;

        let params;
        let matched = true;
        for (let i = 0; i < candidate.segments.length; i += 1) {
          const segment = candidate.segments[i];
          if (segment === null) {
            if (!parts[i]) { matched = false; break; }
            params ??= {};
            params[candidate.keys[i]] = decode(parts[i]);
          } else if (segment !== foldedParts[i]) {
            matched = false;
            break;
          }
        }

        if (matched) return { route: candidate.route, params: params ?? {} };
      }
    }

    return undefined;
  }

  match(method, path) {
    // exact first: a route configured WITH a trailing slash, e.g.
    // routes: { token: '/token/' }, has to keep matching /token/ - trimming
    // before looking up would only ever match /token//
    const exact = this.#lookup(method, path);
    if (exact) return exact;

    if (path.length > 1 && path.charCodeAt(path.length - 1) === 0x2f /* / */) {
      return this.#lookup(method, path.slice(0, -1));
    }

    return undefined;
  }

  url(name, params = {}, options) {
    const path = this.#names.get(name);
    if (path === undefined) return new Error(`No route found for name: ${name}`);

    // @koa/router lifts a truthy `query` out of the params object and treats it
    // as options; device_authorization_response.js relies on it for
    // verification_uri_complete
    let values = params;
    let query = options?.query;
    if (!options && params && params.query) {
      ({ query, ...values } = params);
    }

    const url = path.replace(/\/:([^/]+)/g, (_, key) => {
      // path-to-regexp throws rather than interpolating "undefined"
      if (values[key] === undefined || values[key] === null) {
        throw new TypeError(`Missing parameters: ${key}`);
      }
      return `/${encodeURIComponent(values[key])}`;
    });

    if (query === undefined) return url;

    const search = typeof query === 'string'
      ? query.replace(/^\?/, '')
      : querystring.stringify(query);

    return search ? `${url}?${search}` : url;
  }

  routes() {
    const router = this;
    return function dispatch(ctx, next) {
      const matched = router.match(ctx.method, ctx.path);
      if (!matched) return next();

      // the context @koa/router established, including merging rather than
      // replacing params - a mount or an upstream router may have set some
      ctx.params = { ...ctx.params, ...matched.params };
      if (ctx.request) ctx.request.params = ctx.params;
      ctx.router = router;
      ctx.routerName = matched.route.name;
      ctx.routerPath = matched.route.path;
      ctx._matchedRoute = matched.route.path;
      ctx._matchedRouteName = matched.route.name;

      return matched.route.run(ctx, next);
    };
  }
}
