const crypto = require('crypto');
const { URL } = require('url');
const debug = require('debug')('oidc-provider:authentication:success');

const instance = require('../../helpers/weak_cache');

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
  const res = await next();

  const { oidc: { params, session, uuid }, cookies } = ctx;

  if (params.state !== undefined) res.state = params.state;

  if (instance(provider).configuration('features.sessionManagement')) {
    const salt = crypto.randomBytes(8).toString('hex');
    const state = String(session.authTime());

    const shasum = crypto.createHash('sha256')
      .update(params.client_id)
      .update(' ')
      .update(new URL(params.redirect_uri).origin)
      .update(' ')
      .update(state)
      .update(' ')
      .update(salt);

    const sessionStr = shasum.digest('hex');

    const stateCookieName = `${provider.cookieName('state')}.${params.client_id}`;
    cookies.set(
      stateCookieName, state,
      { ...instance(provider).configuration('cookies.long'), ...{ httpOnly: false } },
    );

    res.session_state = `${sessionStr}.${salt}`;
  }

  provider.emit('authorization.success', ctx);
  debug('uuid=%s %o', uuid, res);

  const handler = instance(provider).responseModes.get(params.response_mode);
  await handler(ctx, params.redirect_uri, res);
};
