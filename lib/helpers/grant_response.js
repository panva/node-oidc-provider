import isPlainObject from './_/is_plain_object.js';

const reserved = new Set([
  'access_token',
  'authorization_details',
  'expires_in',
  'id_token',
  'issued_token_type',
  'refresh_token',
  'scope',
  'token_type',
]);

export function buildTokenResponse(provider, {
  accessToken,
  authorizationDetails,
  expiresIn,
  idToken,
  issuedTokenType,
  parameters = {},
  refreshToken,
  scope,
  tokenType,
} = {}) {
  if (!provider || typeof provider !== 'object') {
    throw new TypeError('provider must be an oidc-provider instance');
  }

  if (typeof accessToken !== 'string' || !accessToken) {
    throw new TypeError('accessToken must be a non-empty string');
  }

  if (typeof tokenType !== 'string' || !tokenType) {
    throw new TypeError('tokenType must be a non-empty string');
  }

  if (!isPlainObject(parameters)) {
    throw new TypeError('parameters must be a plain object');
  }

  for (const name of Object.keys(parameters)) {
    if (reserved.has(name)) {
      throw new TypeError(`parameters must not contain reserved member ${name}`);
    }
  }

  return Object.fromEntries(Object.entries({
    ...parameters,
    access_token: accessToken,
    expires_in: expiresIn,
    id_token: idToken,
    issued_token_type: issuedTokenType,
    refresh_token: refreshToken,
    scope,
    token_type: tokenType,
    authorization_details: authorizationDetails,
  }).filter(([, value]) => value !== undefined));
}
