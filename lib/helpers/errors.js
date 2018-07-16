const { upperFirst, camelCase } = require('lodash');

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

class InvalidToken extends OIDCProviderError {
  constructor() {
    super(401, 'invalid_token');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: 'invalid token provided' });
  }
}

class InvalidClientMetadata extends OIDCProviderError {
  constructor(description) {
    const message = description.startsWith('redirect_uris')
      ? 'invalid_redirect_uri' : 'invalid_client_metadata';
    super(400, message);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      error_description: description,
    });
  }
}

class InvalidScope extends OIDCProviderError {
  constructor(description, scope) {
    super(400, 'invalid_scope');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      scope,
      error_description: description,
    });
  }
}

class InvalidRequest extends OIDCProviderError {
  constructor(description, code = 400) {
    super(code, 'invalid_request');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      error_description: description || 'request is invalid',
      expose: true,
    });
  }
}

class SessionNotFound extends InvalidRequest {}

class InvalidClient extends OIDCProviderError {
  constructor(detail) {
    super(400, 'invalid_client');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      error_description: 'client is invalid',
      error_detail: detail,
    });
  }
}

class InvalidClientAuth extends OIDCProviderError {
  constructor(detail) {
    super(401, 'invalid_client');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      error_description: 'client authentication failed',
      error_detail: detail,
    });
  }
}

class InvalidGrant extends OIDCProviderError {
  constructor(detail) {
    super(400, 'invalid_grant');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, {
      error_description: 'grant request is invalid',
      error_detail: detail,
    });
  }
}

const classes = [
  ['access_denied'],
  ['authorization_pending', 'authorization request is still pending as the end-user hasn\'t yet completed the user interaction steps'],
  ['expired_token'],
  ['invalid_request_object'],
  ['invalid_request_uri'],
  ['redirect_uri_mismatch', 'redirect_uri did not match any client\'s registered redirect_uris'],
  ['web_message_uri_mismatch', 'web_message_uri did not match any client\'s registered web_message_uris'],
  ['registration_not_supported', 'registration parameter provided but not supported'],
  ['request_not_supported', 'request parameter provided but not supported'],
  ['request_uri_not_supported', 'request_uri parameter provided but not supported'],
  ['restricted_grant_type', 'requested grant type is restricted to this client'], // TODO: Deprecated Error, delete in 5.x
  ['restricted_response_type', 'response_type not allowed for this client'], // TODO: Deprecated Error, delete in 5.x
  ['slow_down', 'you are polling too quickly and should back off at a reasonable rate'],
  ['temporarily_unavailable'],
  ['unauthorized_client'],
  ['unsupported_grant_type', 'unsupported grant_type requested'],
  ['unsupported_response_mode', 'unsupported response_mode requested'],
  ['unsupported_response_type', 'unsupported response_type requested'],
];

classes.forEach(([message, errorDescription]) => {
  const klassName = upperFirst(camelCase(message));
  const klass = class extends OIDCProviderError {
    constructor(...args) {
      const description = errorDescription || args[0];
      super(400, message);
      Error.captureStackTrace(this, this.constructor);
      this.error_description = description;
    }
  };
  Object.defineProperty(klass, 'name', { value: klassName });
  module.exports[klassName] = klass;
});

module.exports.InvalidClientAuth = InvalidClientAuth;
module.exports.InvalidClient = InvalidClient;
module.exports.InvalidClientMetadata = InvalidClientMetadata;
module.exports.InvalidGrant = InvalidGrant;
module.exports.InvalidRequest = InvalidRequest;
module.exports.SessionNotFound = SessionNotFound;
module.exports.InvalidScope = InvalidScope;
module.exports.InvalidToken = InvalidToken;
