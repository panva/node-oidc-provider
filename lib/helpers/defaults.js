'use strict';

module.exports = {
  acrValues: ['0', '1', '2'],
  claims: {
    acr: null,
    auth_time: null,
    iss: null,
    openid: {
      sub: null,
    },
  },
  cookies: {
    long: {
      httpOnly: true,
      maxAge: 31557600000, // 1 year
      signed: true,
    },
    short: {
      httpOnly: true,
      maxAge: 60 * 60 * 1000, // 60 minutes
      signed: true,
    },
  },
  discovery: {
    claim_types_supported: ['normal'],
    claims_locales_supported: undefined,
    display_values_supported: undefined,
    op_policy_uri: undefined,
    op_tos_uri: undefined,
    service_documentation: undefined,
    ui_locales_supported: undefined,
  },
  features: {
    backchannelLogout: false,
    claimsParameter: false,
    clientCredentials: false,
    discovery: true,
    encryption: false,
    introspection: false,
    refreshToken: false,
    registration: false,
    registrationManagement: false,
    request: false,
    requestUri: false,
    revocation: false,
    sessionManagement: false,
  },
  timeouts: {
    request_uri: 1500,
    sector_identifier_uri: 1500,
    jwks_uri: 1500,
    backchannel_logout_uri: 1500,
  },
  interactionUrl: ctx => `/interaction/${ctx.oidc.uuid}`,
  prompts: [
    'consent',
    'login',
    'none',
  ],
  renderError: function renderError(ctx, error) {
    ctx.type = 'html';

    ctx.body = `<!DOCTYPE html>
  <head>
    <title>oops! something went wrong</title>
  </head>
  <body>
    <h1>oops! something went wrong</h1>
    <pre>${JSON.stringify(error, null, 4)}</pre>
  </body>
</html>`;
  },
  responseTypes: [
    'code id_token token',
    'code id_token',
    'code token',
    'code',
    'id_token token',
    'id_token',
    'none',
  ],
  routes: {
    authorization: '/auth',
    certificates: '/certs',
    check_session: '/session/check',
    end_session: '/session/end',
    introspection: '/token/introspection',
    registration: '/reg',
    revocation: '/token/revocation',
    token: '/token',
    userinfo: '/me',
  },
  scopes: [
    'address',
    'email',
    'offline_access',
    'openid',
    'phone',
    'profile',
  ],
  subjectTypes: ['public'],
  pairwiseSalt: '',
  tokenEndpointAuthMethods: [
    'none',
    'client_secret_basic',
    'client_secret_jwt',
    'client_secret_post',
    'private_key_jwt',
  ],
  ttl: {
    acr: 5 * 60, // 5 minutes
    AccessToken: 2 * 60 * 60, // 2 hours
    AuthorizationCode: 10 * 60, // 10 minutes
    ClientCredentials: 10 * 60, // 10 minutes
    IdToken: 2 * 60 * 60, // 2 hours
    RefreshToken: 30 * 24 * 60 * 60, // 30 days
  },
  uniqueness: function uniqueness(ctx, jti, expiresAt) { // eslint-disable-line no-unused-vars
    return Promise.resolve(true);
  },
  tokenIntegrity: false,
};
