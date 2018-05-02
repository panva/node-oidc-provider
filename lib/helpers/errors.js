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

class InvalidClientError extends OIDCProviderError {
  constructor(detail) {
    super(400, 'invalid_client');
    Error.captureStackTrace(this, InvalidClientError);
    Object.assign(this, {
      error_description: 'client is invalid',
      error_detail: detail,
    });
  }
}

class InvalidClientAuthError extends OIDCProviderError {
  constructor(detail) {
    super(401, 'invalid_client');
    Error.captureStackTrace(this, InvalidClientAuthError);
    Object.assign(this, {
      error_description: 'client authentication failed',
      error_detail: detail,
    });
  }
}

class InvalidGrantError extends OIDCProviderError {
  constructor(detail) {
    super(400, 'invalid_grant');
    Error.captureStackTrace(this, InvalidGrantError);
    Object.assign(this, {
      error_description: 'grant request is invalid',
      error_detail: detail,
    });
  }
}

class InvalidRequestError extends OIDCProviderError {
  constructor(description, code = 400) {
    super(code, 'invalid_request');
    Error.captureStackTrace(this, InvalidRequestError);
    Object.assign(this, {
      error_description: description || 'request is invalid',
      expose: true,
    });
  }
}

class InvalidTokenError extends OIDCProviderError {
  constructor() {
    super(401, 'invalid_token');
    Error.captureStackTrace(this, InvalidTokenError);
    Object.assign(this, { error_description: 'invalid token provided' });
  }
}

class InvalidClientMetadata extends OIDCProviderError {
  constructor(description) {
    const message = description.startsWith('redirect_uris') ?
      'invalid_redirect_uri' : 'invalid_client_metadata';
    super(400, message);
    Error.captureStackTrace(this, InvalidClientMetadata);
    Object.assign(this, {
      error_description: description,
    });
  }
}

class RedirectUriMismatchError extends OIDCProviderError {
  constructor() {
    super(400, 'redirect_uri_mismatch');
    Error.captureStackTrace(this, RedirectUriMismatchError);
    Object.assign(this, {
      error_description: 'redirect_uri did not match any client\'s registered redirect_uris',
    });
  }
}

class InvalidRequestObject extends OIDCProviderError {
  constructor(description) {
    super(400, 'invalid_request_object');
    Error.captureStackTrace(this, InvalidRequestObject);
    Object.assign(this, {
      error_description: description,
    });
  }
}

class InvalidRequestUri extends OIDCProviderError {
  constructor(description) {
    super(400, 'invalid_request_uri');
    Error.captureStackTrace(this, InvalidRequestUri);
    Object.assign(this, {
      error_description: description,
    });
  }
}

class InvalidScopeError extends OIDCProviderError {
  constructor(description, scope) {
    super(400, 'invalid_scope');
    Error.captureStackTrace(this, InvalidScopeError);
    Object.assign(this, {
      scope,
      error_description: description,
    });
  }
}

class RegistrationNotSupportedError extends OIDCProviderError {
  constructor() {
    super(400, 'registration_not_supported');
    Error.captureStackTrace(this, RegistrationNotSupportedError);
    Object.assign(this, {
      error_description: 'registration parameter provided but not supported',
    });
  }
}

class RequestNotSupportedError extends OIDCProviderError {
  constructor() {
    super(400, 'request_not_supported');
    Error.captureStackTrace(this, RequestNotSupportedError);
    Object.assign(this, {
      error_description: 'request parameter provided but not supported',
    });
  }
}

class RequestUriNotSupportedError extends OIDCProviderError {
  constructor() {
    super(400, 'request_uri_not_supported');
    Error.captureStackTrace(this, RequestUriNotSupportedError);
    Object.assign(this, {
      error_description: 'request_uri parameter provided but not supported',
    });
  }
}

class RestrictedGrantTypeError extends OIDCProviderError {
  constructor() {
    super(400, 'restricted_grant_type');
    Error.captureStackTrace(this, RestrictedGrantTypeError);
    Object.assign(this, {
      error_description: 'requested grant type is restricted to this client',
    });
  }
}

class RestrictedResponseTypeError extends OIDCProviderError {
  constructor() {
    super(400, 'restricted_response_type');
    Error.captureStackTrace(this, RestrictedResponseTypeError);
    Object.assign(this, {
      error_description: 'response_type not allowed for this client',
    });
  }
}

class UnsupportedGrantTypeError extends OIDCProviderError {
  constructor() {
    super(400, 'unsupported_grant_type');
    Error.captureStackTrace(this, UnsupportedGrantTypeError);
    Object.assign(this, {
      error_description: 'unsupported grant_type requested',
    });
  }
}

class UnsupportedResponseModeError extends OIDCProviderError {
  constructor() {
    super(400, 'unsupported_response_mode');
    Error.captureStackTrace(this, UnsupportedResponseModeError);
    Object.assign(this, {
      error_description: 'unsupported response_mode requested',
    });
  }
}

class UnsupportedResponseTypeError extends OIDCProviderError {
  constructor() {
    super(400, 'unsupported_response_type');
    Error.captureStackTrace(this, UnsupportedResponseTypeError);
    Object.assign(this, {
      error_description: 'unsupported response_type requested',
    });
  }
}

module.exports = {
  OIDCProviderError,
  InvalidClientAuthError,
  InvalidClientError,
  InvalidClientMetadata,
  InvalidGrantError,
  InvalidRequestError,
  InvalidRequestObject,
  InvalidRequestUri,
  InvalidScopeError,
  InvalidTokenError,
  RedirectUriMismatchError,
  RegistrationNotSupportedError,
  RequestNotSupportedError,
  RequestUriNotSupportedError,
  RestrictedGrantTypeError,
  RestrictedResponseTypeError,
  UnsupportedGrantTypeError,
  UnsupportedResponseModeError,
  UnsupportedResponseTypeError,
};
