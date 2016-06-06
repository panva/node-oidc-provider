'use strict';

const createError = require('http-errors');

function InvalidClientError(detail) {
  const err = createError(400, 'invalid_client', {
    error_description: 'client is invalid',
  });
  if (detail) {
    err.error_detail = detail;
  }
  return err;
}

function InvalidGrantError(detail) {
  const err = createError(400, 'invalid_grant', {
    error_description: 'grant request is invalid',
  });
  if (detail) {
    err.error_detail = detail;
  }
  return err;
}

function InvalidRequestError(description) {
  return createError(400, 'invalid_request', {
    error_description: description || 'request is invalid',
  });
}

function InvalidTokenError() {
  const err = createError(401, 'invalid_token', {
    error_description: 'invalid token provided',
  });
  return err;
}

function InvalidClientMetadata(description, key) {
  return createError(400, key || 'invalid_client_metadata', {
    error_description: description,
  });
}

function RedirectUriMismatchError() {
  return createError(400, 'redirect_uri_mismatch', {
    error_description:
    'redirect_uri did not match any client\'s registered redirect_uri',
  });
}

module.exports = {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidTokenError,
  InvalidClientMetadata,
  RedirectUriMismatchError,
};
