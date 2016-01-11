'use strict';

let createError = require('http-errors');

module.exports.InvalidClientError = function (detail) {
  let err = createError(400, 'invalid_client', {
    error_description: 'client is invalid',
  });
  if (detail) {
    err.error_detail = detail;
  }
  return err;
};

module.exports.InvalidGrantError = function (detail) {
  let err = createError(400, 'invalid_grant', {
    error_description: 'grant request is invalid',
  });
  if (detail) {
    err.error_detail = detail;
  }
  return err;
};

module.exports.InvalidRequestError = function (description) {
  return createError(400, 'invalid_request', {
    error_description: description || 'request is invalid',
  });
};

module.exports.InvalidTokenError = function (detail) {
  let err = createError(401, 'invalid_token', {
    error_description: 'invalid token provided',
  });
  if (detail) {
    err.error_detail = detail;
  }
  return err;
};

module.exports.InvalidClientMetadata = function (description, key) {
  return createError(400, key || 'invalid_client_metadata', {
    error_description: description || 'provided client metadata is invalid',
  });
};

module.exports.RedirectUriMismatchError = function () {
  return createError(400, 'redirect_uri_mismatch', {
    error_description:
      'redirect_uri did not match any client\'s registered redirect_uri',
  });
};
