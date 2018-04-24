const createError = require('http-errors');

function InvalidClientError(detail) {
  return createError(400, 'invalid_client', {
    error_description: 'client is invalid',
    error_detail: detail,
  });
}

function InvalidClientAuthError(detail) {
  return createError(401, 'invalid_client', {
    error_description: 'client authentication failed',
    error_detail: detail,
  });
}

function InvalidGrantError(detail) {
  return createError(400, 'invalid_grant', {
    error_description: 'grant request is invalid',
    error_detail: detail,
  });
}

function InvalidRequestError(description, code) {
  return createError(code || 400, 'invalid_request', { error_description: description || 'request is invalid', expose: true });
}

function InvalidTokenError() {
  return createError(401, 'invalid_token', { error_description: 'invalid token provided' });
}

function InvalidClientMetadata(description) {
  const message = description.startsWith('redirect_uris') ?
    'invalid_redirect_uri' : 'invalid_client_metadata';
  return createError(400, message, { error_description: description });
}

function RedirectUriMismatchError() {
  return createError(400, 'redirect_uri_mismatch', { error_description: 'redirect_uri did not match any client\'s registered redirect_uris' });
}

module.exports = {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidTokenError,
  InvalidClientMetadata,
  InvalidClientAuthError,
  RedirectUriMismatchError,
};
