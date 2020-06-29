/* eslint-disable max-classes-per-file */

const upperFirst = require('./_/upper_first');
const camelCase = require('./_/camel_case');

class OIDCProviderError extends Error {
  constructor(status, message) {
    super(message);
    this.name = this.constructor.name;
    this.message = message;
    this.error = message;
    this.status = status;
    this.statusCode = status;
    this.expose = status < 500;
  }
}

module.exports.OIDCProviderError = OIDCProviderError;

class InvalidToken extends OIDCProviderError {
  constructor(detail) {
    super(401, 'invalid_token');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: 'invalid token provided', error_detail: detail });
  }
}

class InvalidClientMetadata extends OIDCProviderError {
  constructor(description) {
    const message = description.startsWith('redirect_uris')
      ? 'invalid_redirect_uri' : 'invalid_client_metadata';
    super(400, message);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description });
  }
}

class InvalidScope extends OIDCProviderError {
  constructor(description, scope) {
    super(400, 'invalid_scope');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { scope, error_description: description });
  }
}

class InvalidRequest extends OIDCProviderError {
  constructor(description, code = 400) {
    super(code, 'invalid_request');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description || 'request is invalid', expose: true });
  }
}

class SessionNotFound extends InvalidRequest {}

class InvalidClientAuth extends OIDCProviderError {
  constructor(detail) {
    super(401, 'invalid_client');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: 'client authentication failed', error_detail: detail });
  }
}

class InvalidGrant extends OIDCProviderError {
  constructor(detail) {
    super(400, 'invalid_grant');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: 'grant request is invalid', error_detail: detail });
  }
}

const classes = [
  ['access_denied'],
  ['authorization_pending', 'authorization request is still pending as the end-user hasn\'t yet completed the user interaction steps'],
  ['consent_required'],
  ['expired_token'],
  ['interaction_required'],
  ['invalid_client'],
  ['invalid_dpop_proof'],
  ['invalid_request_object'],
  ['invalid_request_uri'],
  ['invalid_software_statement'],
  ['invalid_target'],
  ['login_required'],
  ['redirect_uri_mismatch', 'redirect_uri did not match any of the client\'s registered redirect_uris'],
  ['registration_not_supported', 'registration parameter provided but not supported'],
  ['request_not_supported', 'request parameter provided but not supported'],
  ['request_uri_not_supported', 'request_uri parameter provided but not supported'],
  ['slow_down', 'you are polling too quickly and should back off at a reasonable rate'],
  ['temporarily_unavailable'],
  ['unapproved_software_statement'],
  ['unauthorized_client'],
  ['unsupported_grant_type', 'unsupported grant_type requested'],
  ['unsupported_response_mode', 'unsupported response_mode requested'],
  ['unsupported_response_type', 'unsupported response_type requested'],
  ['web_message_uri_mismatch', 'web_message_uri did not match any client\'s registered web_message_uris'],
];

module.exports.OIDCProviderError = OIDCProviderError;

classes.forEach(([message, errorDescription]) => {
  const klassName = upperFirst(camelCase(message));
  const klass = class extends OIDCProviderError {
    constructor(description = errorDescription, detail) {
      super(400, message);
      Error.captureStackTrace(this, this.constructor);

      if (description) {
        this.error_description = description;
      }

      if (detail) {
        this.error_detail = detail;
      }
    }
  };
  Object.defineProperty(klass, 'name', { value: klassName });
  module.exports[klassName] = klass;
});

module.exports.InvalidClientAuth = InvalidClientAuth;
module.exports.InvalidClientMetadata = InvalidClientMetadata;
module.exports.InvalidGrant = InvalidGrant;
module.exports.InvalidRequest = InvalidRequest;
module.exports.SessionNotFound = SessionNotFound;
module.exports.InvalidScope = InvalidScope;
module.exports.InvalidToken = InvalidToken;
