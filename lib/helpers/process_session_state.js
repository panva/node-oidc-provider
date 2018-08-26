const { randomBytes, createHash } = require('crypto');
const { URL } = require('url');

const instance = require('./weak_cache');

const webProtocols = new Set(['http:', 'https:']);

function processSessionState(provider, ctx, redirectUri, salt) {
  const { oidc: { session, client }, cookies } = ctx;
  const parsed = new URL(redirectUri);
  const { origin, protocol } = parsed;

  if (client.applicationType === 'native' || !webProtocols.has(protocol)) {
    return undefined;
  }

  const { clientId } = client;
  const state = session.stateFor(clientId);

  const shasum = createHash('sha256')
    .update(clientId)
    .update(' ')
    .update(origin)
    .update(' ')
    .update(state);

  if (salt) shasum.update(` ${salt}`);

  const sessionState = shasum.digest('hex');

  const stateCookieName = `${provider.cookieName('state')}.${clientId}`;
  cookies.set(
    stateCookieName, state,
    { ...instance(provider).configuration('cookies.long'), httpOnly: false },
  );

  return salt ? `${sessionState}.${salt}` : sessionState;
}

module.exports = processSessionState;
module.exports.salted = function saltedProcessSessionState(provider, ctx, redirectUri) {
  const salt = randomBytes(8).toString('hex');
  return processSessionState(provider, ctx, redirectUri, salt);
};
