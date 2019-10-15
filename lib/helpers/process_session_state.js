const { randomBytes, createHash } = require('crypto');
const { URL } = require('url');

const base64url = require('./base64url');
const instance = require('./weak_cache');
const ssHandler = require('./samesite_handler');

function processSessionState(ctx, redirectUri, salt) {
  const { oidc } = ctx;
  const parsed = new URL(redirectUri);
  const { origin } = parsed;

  const { clientId } = oidc.client;
  const state = oidc.session.stateFor(clientId);

  const shasum = createHash('sha256')
    .update(clientId)
    .update(' ')
    .update(origin)
    .update(' ')
    .update(state);

  if (salt) {
    shasum.update(' ');
    shasum.update(salt);
  }

  const sessionState = base64url.encodeBuffer(shasum.digest());

  const stateCookieName = `${oidc.provider.cookieName('state')}.${clientId}`;
  ssHandler.set(
    oidc.cookies,
    stateCookieName,
    state,
    { ...instance(oidc.provider).configuration('cookies.long'), httpOnly: false, signed: false },
  );

  return salt ? `${sessionState}.${salt}` : sessionState;
}

module.exports = processSessionState;
module.exports.salted = function saltedProcessSessionState(ctx, redirectUri) {
  const salt = base64url.encodeBuffer(randomBytes(8));
  return processSessionState(ctx, redirectUri, salt);
};
