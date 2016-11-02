'use strict';

const crypto = require('crypto');
const url = require('url');

const instance = require('../../helpers/weak_cache');
const redirectUri = require('../../helpers/redirect_uri');
const formPost = require('../../shared/form_post');

function locationOrigin(uri) {
  return url.format(Object.assign(url.parse(uri), {
    hash: null,
    pathname: null,
    search: null,
  }));
}

/*
 * Based on the authorization request response mode either redirects with parameters in query or
 * fragment or renders auto-submitting form with the response members as hidden fields.
 *
 * If session management is supported stores User-Agent readable cookie with the session stated
 * used by the OP iframe to detect session state changes.
 *
 * @emits: authorization.success
 */
module.exports = provider => function* respond(next) {
  const out = yield next;

  if (this.oidc.params.state !== undefined) out.state = this.oidc.params.state;

  provider.emit('authorization.success', this);

  if (instance(provider).configuration('features.sessionManagement')) {
    const salt = crypto.randomBytes(8).toString('hex');
    const state = String(this.oidc.session.authTime());

    const shasum = crypto.createHash('sha256')
      .update(this.oidc.params.client_id)
      .update(' ')
      .update(locationOrigin(this.oidc.params.redirect_uri))
      .update(' ')
      .update(state)
      .update(' ')
      .update(salt);

    const sessionStr = shasum.digest('hex');

    const stateCookieName = `_state.${this.oidc.params.client_id}`;
    this.cookies.set(stateCookieName, state,
      Object.assign({}, instance(provider).configuration('cookies.long'), { httpOnly: false }));

    out.session_state = `${sessionStr}.${salt}`;
  }

  if (instance(provider).responseModes.has(this.oidc.params.response_mode)) {
    instance(provider).responseModes.get(this.oidc.params.response_mode)
      .call(this, this.oidc.params.redirect_uri, out);
  } else if (this.oidc.params.response_mode === 'form_post') {
    formPost.call(this, this.oidc.params.redirect_uri, out);
  } else {
    const uri = redirectUri(this.oidc.params.redirect_uri, out, this.oidc.params.response_mode);
    this.redirect(uri);
  }
};
