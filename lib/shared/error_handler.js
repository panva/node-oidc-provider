import debug from 'debug';

import instance from '../helpers/weak_cache.js';
import * as formHtml from '../helpers/user_code_form.js';
import { ReRenderError } from '../helpers/re_render_errors.js';
import errOut from '../helpers/err_out.js';

import { generateXsrf } from './xsrf.js';

// TODO(v10): replace `debug` with node:util.debuglog. It is the last dependency
// here that is not jose or koa, and with @koa/router gone nothing else pulls it
// in, so dropping it saves 49,514 bytes and 11 files - debug plus ms - for six
// log statements across this file and authorization_error_handler.js. The
// namespaces map over unchanged, but the selector becomes
// NODE_DEBUG=oidc-provider* rather than DEBUG=oidc-provider:*, and the line
// format becomes node's, so it needs a major. Note debug's %o is a single line
// inspect where util.format's is multi-line and shows hidden properties.
const debugError = debug('oidc-provider:error');
const serverError = debug('oidc-provider:server_error');
const serverErrorTrace = debug('oidc-provider:server_error:trace');

const userInputRoutes = new Set(['code_verification', 'device_resume']);

export default function getErrorHandler(eventName) {
  return async function errorHandler(ctx, next) {
    const { provider } = ctx.oidc;
    const {
      features: { deviceFlow: { charset, userCodeInputSource } },
    } = instance(provider).configuration;

    try {
      await next();
    } catch (err) {
      const out = errOut(err);
      ctx.status = err.statusCode || 500;

      if (err.expose && !(err instanceof ReRenderError)) {
        debugError('path=%s method=%s error=%o detail=%s', ctx.path, ctx.method, out, err.error_detail);
      } else if (!(err instanceof ReRenderError)) {
        serverError('path=%s method=%s error=%o', ctx.path, ctx.method, err);
        serverErrorTrace(err);
      }

      if (ctx.oidc?.session && userInputRoutes.has(ctx.oidc.route)) {
        generateXsrf(ctx, () => {});
        const { secret } = ctx.oidc.session.state;

        await userCodeInputSource(ctx, formHtml.input(ctx.oidc.urlFor('code_verification'), secret, err.userCode, charset), out, err);
        if (err instanceof ReRenderError) { // render without emit
          return;
        }
      } else if (ctx.accepts('json', 'html') === 'html') {
        // this ^^ makes */* requests respond with json (curl, xhr, request libraries), while in
        // browser requests end up rendering the html error instead
        const { renderError } = instance(provider).configuration;
        await renderError(ctx, out, err);
      } else {
        ctx.body = out;
      }

      if (out.error === 'server_error') {
        provider.emit('server_error', ctx, err);
      } else if (eventName) {
        provider.emit(eventName, ctx, err);
      }
    }
  };
}
