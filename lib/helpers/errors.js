/* eslint-disable camelcase */
/* eslint-disable max-classes-per-file */

const upperFirst = require('./_/upper_first');
const camelCase = require('./_/camel_case');

class OIDCProviderError extends Error {
  allow_redirect = true;

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

class CustomOIDCProviderError extends OIDCProviderError {
  constructor(message, description) {
    super(400, message);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description });
  }
}

class InvalidToken extends OIDCProviderError {
  error_description = 'invalid token provided';

  constructor(detail) {
    super(401, 'invalid_token');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

class InvalidClientMetadata extends OIDCProviderError {
  constructor(description, detail) {
    const message = description.startsWith('redirect_uris')
      ? 'invalid_redirect_uri' : 'invalid_client_metadata';
    super(400, message);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description, error_detail: detail });
  }
}

class InvalidScope extends OIDCProviderError {
  constructor(description, scope, detail) {
    super(400, 'invalid_scope');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { scope, error_description: description, error_detail: detail });
  }
}

class InvalidRequest extends OIDCProviderError {
  constructor(description, code = 400, detail) {
    super(code, 'invalid_request');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description || 'request is invalid', error_detail: detail, expose: true });
  }
}

class SessionNotFound extends InvalidRequest {}

class InvalidClientAuth extends OIDCProviderError {
  error_description = 'client authentication failed';

  constructor(detail) {
    super(401, 'invalid_client');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

class InvalidGrant extends OIDCProviderError {
  error_description = 'grant request is invalid';

  constructor(detail) {
    super(400, 'invalid_grant');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

class InvalidRedirectUri extends OIDCProviderError {
  error_description = 'redirect_uri did not match any of the client\'s registered redirect_uris';

  allow_redirect = false;

  constructor() {
    super(400, 'invalid_redirect_uri');
    Error.captureStackTrace(this, this.constructor);
  }
}

class WebMessageUriMismatch extends OIDCProviderError {
  error_description = 'web_message_uri did not match any client\'s registered web_message_uris';

  allow_redirect = false;

  constructor() {
    super(400, 'web_message_uri_mismatch');
    Error.captureStackTrace(this, this.constructor);
  }
}

const classes = [
  ['access_denied'],
  ['authorization_pending', 'authorization request is still pending as the end-user hasn\'t yet completed the user interaction steps'],
  ['consent_required'],
  ['expired_login_hint_token'],
  ['expired_token'],
  ['interaction_required'],
  ['invalid_binding_message'],
  ['invalid_client'],
  ['invalid_dpop_proof'],
  ['invalid_request_object'],
  ['invalid_request_uri'],
  ['invalid_software_statement'],
  ['invalid_target', 'resource indicator is missing, or unknown'],
  ['invalid_user_code'],
  ['login_required'],
  ['missing_user_code'],
  ['registration_not_supported', 'registration parameter provided but not supported'],
  ['request_not_supported', 'request parameter provided but not supported'],
  ['request_uri_not_supported', 'request_uri parameter provided but not supported'],
  ['slow_down', 'you are polling too quickly and should back off at a reasonable rate'],
  ['temporarily_unavailable'],
  ['transaction_failed'],
  ['unapproved_software_statement'],
  ['unauthorized_client'],
  ['unknown_user_id'],
  ['unsupported_grant_type', 'unsupported grant_type requested'],
  ['unsupported_response_mode', 'unsupported response_mode requested'],
  ['unsupported_response_type', 'unsupported response_type requested'],
];

module.exports.OIDCProviderError = OIDCProviderError;

classes.forEach(([message, errorDescription]) => {
  const klassName = upperFirst(camelCase(message));
  const klass = class extends OIDCProviderError {
    error_description = errorDescription;

    constructor(description, detail) {
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

module.exports.CustomOIDCProviderError = CustomOIDCProviderError;
module.exports.InvalidClientAuth = InvalidClientAuth;
module.exports.InvalidClientMetadata = InvalidClientMetadata;
module.exports.InvalidGrant = InvalidGrant;
module.exports.InvalidRedirectUri = InvalidRedirectUri;
module.exports.InvalidRequest = InvalidRequest;
module.exports.InvalidScope = InvalidScope;
module.exports.InvalidToken = InvalidToken;
module.exports.OIDCProviderError = OIDCProviderError;
module.exports.SessionNotFound = SessionNotFound;
module.exports.WebMessageUriMismatch = WebMessageUriMismatch;
