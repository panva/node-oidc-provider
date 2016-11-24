'use strict';

const LRU = require('lru-cache');
const epochTime = require('../helpers/epoch_time');

const cache = new LRU(100);

module.exports = {


  /*
   * acrValues
   *
   * description: list of the Authentication Context Class References that OP supports
   * affects: discovery, ID Token acr claim values
   */
  acrValues: ['0', '1', '2'],


  /*
   * claims
   *
   * description: list of the Claim Names of the Claims that the OpenID Provider MAY be able to
   *   supply values for
   * affects: discovery, ID Token claim names, Userinfo claim names
   */
  claims: { acr: null, auth_time: null, iss: null, openid: { sub: null } },


  /*
   * cookies
   *
   * description: options for https://github.com/pillarjs/cookies#cookiesset-name--value---options--
   *   used by the OP to keep track of various User-Agent states
   * affects: User-Agent sessions, passing of authorization details to interaction
   */
  cookies: {
    /*
     * cookies.long
     *
     * description: options for long-term cookies
     * affects: User-Agent session reference, Session Management states
     */
    long: { httpOnly: true, maxAge: (365.25 * 24 * 60 * 60) * 1000 }, // 1 year in ms
    /*
     * cookies.short
     *
     * description: options for short-term cookies
     * affects: passing of authorization details to interaction
     */
    short: { httpOnly: true, maxAge: (60 * 60) * 1000 }, // 60 minutes in ms
  },


  /*
   * discovery
   *
   * description: pass additional properties to this object to extend the discovery document
   * affects: discovery
   */
  discovery: {
    claim_types_supported: ['normal'],
    claims_locales_supported: undefined,
    display_values_supported: undefined,
    op_policy_uri: undefined,
    op_tos_uri: undefined,
    service_documentation: undefined,
    ui_locales_supported: undefined,
  },


  /*
   * extraParams
   *
   * description: pass an iterable object (i.e. array or set) to extend the parameters recognized
   *  by the authorization endpoint. These parameters are then available in ctx.oidc.params as well
   *  as passed via the _grant cookie to interaction
   * affects: authorization, interaction
   */
  extraParams: [],


  /*
   * features
   *
   * description: enable/disable feature 'packs', see configuration.md for more details
   */
  features: {
    devInteractions: true,
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


  /*
   * prompts
   *
   * description: list of the prompt values that the OpenID Provider MAY be able to resolve
   * affects: authorization
   */
  prompts: ['consent', 'login', 'none'],


  /*
   * responseTypes
   *
   * description: list of the OAuth 2.0 response_type values that OP supports
   * affects: authorization, discovery, registration, registration management
   */
  responseTypes: [
    'code id_token token',
    'code id_token',
    'code token',
    'code',
    'id_token token',
    'id_token',
    'none',
  ],


  /*
   * routes
   *
   * description: routing values used by the OP
   * affects: routing
   */
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


  /*
   * scopes
   *
   * description: list of the scope values that the OP supports
   * affects: discovery, authorization, ID Token claims, Userinfo claims
   */
  scopes: ['address', 'email', 'offline_access', 'openid', 'phone', 'profile'],


  /*
   * subjectTypes
   *
   * description: list of the Subject Identifier types that this OP supports. Valid types include
   *   pairwise and public.
   * affects: discovery, registration, registration management, ID Token and Userinfo sub claim
   *   values
   */
  subjectTypes: ['public'],


  /*
   * pairwiseSalt
   *
   * description: Salt used by OP when resolving pairwise ID Token and Userinfo sub claim value
   * affects: ID Token and Userinfo sub claim values
   */
  pairwiseSalt: '',


  /*
   * tokenEndpointAuthMethods
   *
   * description: list of Client Authentication methods supported by this OP's Token Endpoint
   * affects: discovery, client authentication for token, introspection and revocation endpoints,
   *   registration, registration management
   */
  tokenEndpointAuthMethods: [
    'none',
    'client_secret_basic',
    'client_secret_jwt',
    'client_secret_post',
    'private_key_jwt',
  ],


  /*
   * ttl
   *
   * description: expirations (in seconds) for all token types
   * affects: tokens
   */
  ttl: {
    AccessToken: 2 * 60 * 60, // 2 hours in seconds
    AuthorizationCode: 10 * 60, // 10 minutes in seconds
    ClientCredentials: 10 * 60, // 10 minutes in seconds
    IdToken: 2 * 60 * 60, // 2 hours in seconds
    RefreshToken: 30 * 24 * 60 * 60, // 30 days in seconds
  },


  /*
   * postLogoutRedirectUri
   *
   * description: URL to which the OP redirects the User-Agent when no post_logout_redirect_uri
   *   is provided by the RP
   * affects: session management
   */
  postLogoutRedirectUri: '/?loggedOut=true',


  /*
   * logoutSource
   *
   * description: HTML source to which a logout form source is passed when session management
   *   renders a confirmation prompt for the User-Agent.
   * affects: session management
   */
  logoutSource: function logoutSource(form) {
    this.body = `<!DOCTYPE html>
<head>
  <title>Logout</title>
</head>
<body>
  ${form}
  Do you want to logout from OP too?
  <button type="submit" form="op.logoutForm" name="logout" value="yes">Yes</button>
  <button type="submit" form="op.logoutForm">Please, don't!</button>
</body>
</html>`;
  },


  /*
   * uniqueness
   *
   * description: function resolving whether a given value with expiration is presented first time
   * affects: client_secret_jwt and private_key_jwt client authentications
   */
  uniqueness: function uniqueness(jti, expiresAt) {
    // this => koa context;
    if (cache.get(jti)) return Promise.resolve(false);

    cache.set(jti, true, (expiresAt - epochTime()) * 1000);

    return Promise.resolve(true);
  },


  /*
   * renderError
   *
   * description: helper used by the OP to present errors which are not meant to be 'forwarded' to
   *   the RP's redirect_uri
   * affects: presentation of errors encountered during authorization
   */
  renderError: function renderError(error) {
    this.type = 'html';

    this.body = `<!DOCTYPE html>
<head>
  <title>oops! something went wrong</title>
</head>
<body>
  <h1>oops! something went wrong</h1>
  <pre>${JSON.stringify(error, null, 4)}</pre>
</body>
</html>`;
  },


  /*
   * interactionUrl
   *
   * description: helper used by the OP to determine where to redirect User-Agent for necessary
   *   interaction
   * affects: authorization interactions
   * note: can return both absolute and relative urls
   */
  interactionUrl: function interactionUrl(interaction) { // eslint-disable-line no-unused-vars
    // this => koa context;
    return `/interaction/${this.oidc.uuid}`;
  },
};
