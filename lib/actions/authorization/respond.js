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
module.exports = provider => async function respond(ctx, next) {
  const out = await next();

  const { oidc: { params, uuid } } = ctx;

  if (params.state !== undefined) out.state = params.state;

  if (instance(provider).configuration('features.sessionManagement')) {
    const sessionState = processSessionState(provider, ctx, params.redirect_uri);
    if (sessionState) {
      out.session_state = sessionState;
    }
  }

  provider.emit('authorization.success', ctx);
  debug('uuid=%s %o', uuid, out);

  const handler = instance(provider).responseModes.get(params.response_mode);
  await handler(ctx, params.redirect_uri, out);
};
