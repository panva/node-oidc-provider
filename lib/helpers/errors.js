/* eslint-disable camelcase */
/* eslint-disable max-classes-per-file */

import upperFirst from './_/upper_first.js';
import camelCase from './_/camel_case.js';

export class OIDCProviderError extends Error {
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

export class CustomOIDCProviderError extends OIDCProviderError {
  constructor(message, description) {
    super(400, message);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description });
  }
}

export class InvalidToken extends OIDCProviderError {
  error_description = 'invalid token provided';

  constructor(detail) {
    super(401, 'invalid_token');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

export class InvalidClientMetadata extends OIDCProviderError {
  constructor(description, detail) {
    const message = description.startsWith('redirect_uris')
      ? 'invalid_redirect_uri' : 'invalid_client_metadata';
    super(400, message);
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description, error_detail: detail });
  }
}

export class InvalidScope extends OIDCProviderError {
  constructor(description, scope, detail) {
    super(400, 'invalid_scope');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { scope, error_description: description, error_detail: detail });
  }
}

export class InsufficientScope extends OIDCProviderError {
  constructor(description, scope, detail) {
    super(403, 'insufficient_scope');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { scope, error_description: description, error_detail: detail });
  }
}

export class InvalidRequest extends OIDCProviderError {
  constructor(description, code, detail) {
    super(code ?? 400, 'invalid_request');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_description: description || 'request is invalid', error_detail: detail, expose: true });
  }
}

export class SessionNotFound extends InvalidRequest {}

export class InvalidClientAuth extends OIDCProviderError {
  error_description = 'client authentication failed';

  constructor(detail) {
    super(401, 'invalid_client');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

export class InvalidGrant extends OIDCProviderError {
  error_description = 'grant request is invalid';

  constructor(detail) {
    super(400, 'invalid_grant');
    Error.captureStackTrace(this, this.constructor);
    Object.assign(this, { error_detail: detail });
  }
}

export class InvalidRedirectUri extends OIDCProviderError {
  error_description = 'redirect_uri did not match any of the client\'s registered redirect_uris';

  allow_redirect = false;

  constructor() {
    super(400, 'invalid_redirect_uri');
    Error.captureStackTrace(this, this.constructor);
  }
}

export class WebMessageUriMismatch extends OIDCProviderError {
  error_description = 'web_message_uri did not match any client\'s registered web_message_uris';

  allow_redirect = false;

  constructor() {
    super(400, 'web_message_uri_mismatch');
    Error.captureStackTrace(this, this.constructor);
  }
}

function E(message, errorDescription) {
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
  return klass;
}

export const AccessDenied = E('access_denied');
export const AuthorizationPending = E('authorization_pending', 'authorization request is still pending as the end-user hasn\'t yet completed the user interaction steps');
export const ConsentRequired = E('consent_required');
export const ExpiredLoginHintToken = E('expired_login_hint_token');
export const ExpiredToken = E('expired_token');
export const InteractionRequired = E('interaction_required');
export const InvalidBindingMessage = E('invalid_binding_message');
export const InvalidClient = E('invalid_client');
export const InvalidDpopProof = E('invalid_dpop_proof');
export const InvalidRequestObject = E('invalid_request_object');
export const InvalidRequestUri = E('invalid_request_uri');
export const InvalidSoftwareStatement = E('invalid_software_statement');
export const InvalidTarget = E('invalid_target', 'resource indicator is missing, or unknown');
export const InvalidUserCode = E('invalid_user_code');
export const LoginRequired = E('login_required');
export const MissingUserCode = E('missing_user_code');
export const RegistrationNotSupported = E('registration_not_supported', 'registration parameter provided but not supported');
export const RequestNotSupported = E('request_not_supported', 'request parameter provided but not supported');
export const RequestUriNotSupported = E('request_uri_not_supported', 'request_uri parameter provided but not supported');
export const SlowDown = E('slow_down', 'you are polling too quickly and should back off at a reasonable rate');
export const TemporarilyUnavailable = E('temporarily_unavailable');
export const TransactionFailed = E('transaction_failed');
export const UnapprovedSoftwareStatement = E('unapproved_software_statement');
export const UnauthorizedClient = E('unauthorized_client');
export const UnknownUserId = E('unknown_user_id');
export const UnmetAuthenticationRequirements = E('unmet_authentication_requirements');
export const UnsupportedGrantType = E('unsupported_grant_type', 'unsupported grant_type requested');
export const UnsupportedResponseMode = E('unsupported_response_mode', 'unsupported response_mode requested');
export const UnsupportedResponseType = E('unsupported_response_type', 'unsupported response_type requested');
export const UseDpopNonce = E('use_dpop_nonce');
