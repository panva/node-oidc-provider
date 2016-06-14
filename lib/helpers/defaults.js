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
  features: {
    claimsParameter: false,
    clientCredentials: false,
    discovery: true,
    encryption: false,
    introspection: false,
    refreshToken: false,
    registration: false,
    request: false,
    requestUri: false,
    revocation: false,
    sessionManagement: false,
  },
  timeouts: {
    request_uri: 1500,
    sector_identifier_uri: 1500,
    jwks_uri: 1500,
  },
  interactionPath: function interactionPath(grant) {
    return `/interaction/${grant}`;
  },
  prompts: [
    'consent',
    'login',
    'none',
  ],
  renderError: function renderError(error) {
    this.type = 'html';

    this.body = `<!DOCTYPE html>
  <head>
    <title>oops something went wrong</title>
  </head>
  <body>
    ${JSON.stringify(error)}
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
    authentication: '/auth',
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
  subjectTypes: ['public', 'pairwise'],
  pairwiseSalt: '',
  tokenEndpointAuthMethods: [
    'none',
    'client_secret_basic',
    'client_secret_jwt',
    'client_secret_post',
    'private_key_jwt',
  ],
  ttl: {
    acr: 1 * 60,
    accessToken: 5 * 60,
    authorizationCode: 1 * 60,
    clientCredentials: 1 * 60,
    idToken: 5 * 60,
    refreshToken: 30 * 60,
  },
  uniqueness: function uniqueness() {
    return Promise.resolve(true);
  },
};
