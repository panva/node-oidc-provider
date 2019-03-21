const debug = require('debug')('oidc-provider:authentication:success');

const instance = require('../../helpers/weak_cache');
const processSessionState = require('../../helpers/process_session_state');

/*
 * Based on the authorization request response mode either redirects with parameters in query or
 * fragment or renders auto-submitting form with the response members as hidden fields.
 *
 * If session management is supported stores User-Agent readable cookie with the session stated
 * used by the OP iframe to detect session state changes.
 *
 * @emits: authorization.success
 */
module.exports = async function respond(ctx, next) {
  const out = await next();

  const { oidc: { params } } = ctx;

  if (params.state !== undefined) out.state = params.state;

  if (instance(ctx.oidc.provider).configuration('features.sessionManagement.enabled')) {
    const sessionState = processSessionState(ctx, params.redirect_uri);
    if (sessionState) {
      out.session_state = sessionState;
    }
  }

  ctx.oidc.provider.emit('authorization.success', ctx, out);
  debug('uid=%s %o', ctx.oidc.uid, out);

  const handler = instance(ctx.oidc.provider).responseModes.get(params.response_mode);
  await handler(ctx, params.redirect_uri, out);
};
