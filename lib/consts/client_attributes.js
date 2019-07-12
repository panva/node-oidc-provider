const RECOGNIZED_METADATA = [
  'application_type',
  'client_id_issued_at',
  'client_id',
  'client_name',
  'client_secret_expires_at',
  'client_secret',
  'client_uri',
  'contacts',
  'default_acr_values',
  'default_max_age',
  'grant_types',
  'id_token_signed_response_alg',
  'initiate_login_uri',
  'jwks_uri',
  'jwks',
  'logo_uri',
  'policy_uri',
  'post_logout_redirect_uris',
  'redirect_uris',
  'require_auth_time',
  'response_types',
  'scope',
  'sector_identifier_uri',
  'subject_type',
  'token_endpoint_auth_method',
  'tos_uri',
];

const DEFAULT = {
  application_type: 'web',
  grant_types: ['authorization_code'],
  id_token_signed_response_alg: 'RS256',
  require_auth_time: false,
  response_types: ['code'],
  subject_type: 'public',
  token_endpoint_auth_method: 'client_secret_basic',
  introspection_signed_response_alg: 'RS256',
  authorization_signed_response_alg: 'RS256',
  post_logout_redirect_uris: [],
  backchannel_logout_session_required: false,
  frontchannel_logout_session_required: false,
};

const REQUIRED = [
  'client_id',
  // 'client_secret', => validated elsewhere and only needed somewhen
  'redirect_uris',
];

const BOOL = [
  'backchannel_logout_session_required',
  'frontchannel_logout_session_required',
  'require_auth_time',
  'tls_client_certificate_bound_access_tokens',
];

const ARYS = [
  'contacts',
  'default_acr_values',
  'grant_types',
  'redirect_uris',
  'post_logout_redirect_uris',
  'request_uris',
  'response_types',
  'web_message_uris',
];

const STRING = [
  'application_type',
  'backchannel_logout_uri',
  'client_id',
  'client_name',
  'client_secret',
  'client_uri',
  'frontchannel_logout_uri',
  'id_token_encrypted_response_alg',
  'id_token_encrypted_response_enc',
  'id_token_signed_response_alg',
  'initiate_login_uri',
  'jwks_uri',
  'logo_uri',
  'policy_uri',
  'request_object_encryption_alg',
  'request_object_encryption_enc',
  'request_object_signing_alg',
  'scope',
  'sector_identifier_uri',
  'subject_type',
  'tls_client_auth_san_dns',
  'tls_client_auth_san_email',
  'tls_client_auth_san_ip',
  'tls_client_auth_san_uri',
  'tls_client_auth_subject_dn',
  'token_endpoint_auth_method',
  'tos_uri',
  'userinfo_encrypted_response_alg',
  'userinfo_encrypted_response_enc',
  'userinfo_signed_response_alg',
  'introspection_encrypted_response_alg',
  'introspection_encrypted_response_enc',
  'introspection_signed_response_alg',
  'authorization_encrypted_response_alg',
  'authorization_encrypted_response_enc',
  'authorization_signed_response_alg',

  // must be after token_endpoint_auth_method
  'introspection_endpoint_auth_method',
  'revocation_endpoint_auth_method',

  // in arrays
  'contacts',
  'default_acr_values',
  'grant_types',
  'post_logout_redirect_uris',
  'redirect_uris',
  'request_uris',
  'response_types',
  'web_message_uris',
];

const WHEN = {
  id_token_encrypted_response_enc: ['id_token_encrypted_response_alg', 'A128CBC-HS256'],
  request_object_encryption_enc: ['request_object_encryption_alg', 'A128CBC-HS256'],
  userinfo_encrypted_response_enc: ['userinfo_encrypted_response_alg', 'A128CBC-HS256'],
  introspection_encrypted_response_enc: ['introspection_encrypted_response_alg', 'A128CBC-HS256'],
  authorization_encrypted_response_enc: ['authorization_encrypted_response_alg', 'A128CBC-HS256'],
};

const WEB_URI = [
  'backchannel_logout_uri',
  'client_uri',
  'frontchannel_logout_uri',
  'initiate_login_uri',
  'jwks_uri',
  'logo_uri',
  'policy_uri',
  'sector_identifier_uri',
  'tos_uri',

  // in arrays
  'request_uris',
];

const HTTPS_URI = [
  'initiate_login_uri',
  'sector_identifier_uri',
];

const LOOPBACKS = ['localhost', '127.0.0.1', '[::1]'];

const ENUM = {
  application_type: () => ['native', 'web'],
};

module.exports = {
  ARYS,
  BOOL,
  DEFAULT,
  ENUM,
  HTTPS_URI,
  LOOPBACKS,
  RECOGNIZED_METADATA,
  REQUIRED,
  STRING,
  WEB_URI,
  WHEN,
};
