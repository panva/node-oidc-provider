const LRU = require('lru-cache');
const epochTime = require('../helpers/epoch_time');

const cache = new LRU(100);

const warned = new Set();
function changeme(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    console.log(`NOTICE: default helper ${name} called, you should probably change it in order to ${msg}.`); // eslint-disable-line no-console
  }
}

const DEFAULTS = {


  /*
   * acrValues
   *
   * description: Array of strings, the Authentication Context Class References that OP supports.
   *   First one in the list will be the one used for authentication requests unless one was
   *   provided as part of an interaction result. Use a value with 'session' meaning as the first.
   * affects: discovery, ID Token acr claim values
   */
  acrValues: [],


  /*
   * claims
   *
   * description: List of the Claim Names of the Claims that the OpenID Provider MAY be able to
   *   supply values for.
   * affects: discovery, ID Token claim names, Userinfo claim names
   */
  claims: {
    acr: null, auth_time: null, iss: null, openid: ['sub'],
  },


  /*
   * clientCacheDuration
   *
   * description: A `Number` value (in seconds) describing how long a dynamically loaded client
   *    should remain cached.
   * affects: adapter-backed client cache duration
   */
  clientCacheDuration: Infinity,


  /*
   * clockTolerance
   *
   * description: A `Number` value (in seconds) describing the allowed system clock skew
   * affects: JWT (ID token, client assertion) validations.
   */
  clockTolerance: 0,


  /*
   * cookies
   *
   * description: Options for https://github.com/pillarjs/cookies#cookiesset-name--value---options--
   *   used by the OP to keep track of various User-Agent states.
   * affects: User-Agent sessions, passing of authorization details to interaction
   */
  cookies: {
    /*
     * cookies.names
     *
     * description: Cookie names used by the OP to store and transfer various states.
     * affects: User-Agent session, Session Management states and interaction cookie names
     */
    names: {
      session: '_session', // used for main session reference
      interaction: '_grant', // used by the interactions for interaction session reference
      resume: '_grant', // used when interactions resume authorization for interaction session reference
      state: '_state', // prefix for sessionManagement state cookies => _state.{clientId}
    },

    /*
     * cookies.long
     *
     * description: Options for long-term cookies
     * affects: User-Agent session reference, Session Management states
     */
    long: { httpOnly: true, maxAge: (365.25 * 24 * 60 * 60) * 1000 }, // 1 year in ms
    /*
     * cookies.short
     *
     * description: Options for short-term cookies
     * affects: passing of authorization details to interaction
     */
    short: { httpOnly: true, maxAge: (60 * 60) * 1000 }, // 60 minutes in ms
  },


  /*
   * discovery
   *
   * description: Pass additional properties to this object to extend the discovery document
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
   * description: Pass an iterable object (i.e. array or set of strings) to extend the parameters
   *  recognized by the authorization endpoint. These parameters are then available in
   *  ctx.oidc.params as well as passed via the `_grant` cookie to interaction
   * affects: authorization, interaction
   */
  extraParams: [],


  /*
   * features
   *
   * description: Enable/disable features, see configuration.md for more details
   */
  features: {
    devInteractions: true,
    discovery: true,
    requestUri: true,
    oauthNativeApps: true,
    pkce: true,

    backchannelLogout: false,
    frontchannelLogout: false,
    claimsParameter: false,
    clientCredentials: false,
    encryption: false,
    introspection: false,
    alwaysIssueRefresh: false,
    registration: false,
    registrationManagement: false,
    request: false,
    revocation: false,
    sessionManagement: false,
  },


  /*
   * prompts
   *
   * description: List of the prompt values that the OpenID Provider MAY be able to resolve
   * affects: authorization
   */
  prompts: ['consent', 'login', 'none'],


  /*
   * responseTypes
   *
   * description: List of response_type values that OP supports
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
   * description: Routing values used by the OP
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
   * description: List of the scope values that the OP supports
   * affects: discovery, authorization, ID Token claims, Userinfo claims
   */
  scopes: ['openid', 'offline_access'],


  /*
   * subjectTypes
   *
   * description: List of the Subject Identifier types that this OP supports. Valid types include
   *   'pairwise' and 'public'.
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
   * description: List of Client Authentication methods supported by this OP's Token Endpoint
   * affects: discovery, client authentication for token endpoint, registration and
   * registration management
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
   * description: Expirations (in seconds) for all token types
   * affects: tokens
   */
  ttl: {
    AccessToken: 60 * 60, // 1 hour in seconds
    AuthorizationCode: 10 * 60, // 10 minutes in seconds
    ClientCredentials: 10 * 60, // 10 minutes in seconds
    IdToken: 60 * 60, // 1 hour in seconds
    RefreshToken: 14 * 24 * 60 * 60, // 14 days in seconds
  },


  /*
   * postLogoutRedirectUri
   *
   * description: URL to which the OP redirects the User-Agent when no post_logout_redirect_uri
   *   is provided by the RP
   * affects: session management
   */
  async postLogoutRedirectUri(ctx) { // eslint-disable-line no-unused-vars
    changeme('postLogoutRedirectUri', 'specify where to redirect the user after logout without post_logout_redirect_uri specified or validated');
    return ctx.origin;
  },


  /*
   * logoutSource
   *
   * description: HTML source to which a logout form source is passed when session management
   *   renders a confirmation prompt for the User-Agent.
   * affects: session management
   */
  async logoutSource(ctx, form) {
    changeme('logoutSource', 'customize the look of the logout page');
    ctx.body = `<!DOCTYPE html>
<head>
  <title>Logout</title>
</head>
<body>
  <script>
    function logout() {
      var form = document.forms[0];
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'logout';
      input.value = 'yes';
      form.appendChild(input);
      form.submit();
    }
  </script>
  ${form}
  Do you want to logout from OP too?
  <button onclick="logout()">Yes</button>
  <button onclick="document.forms[0].submit()">Please, don't!</button>
</body>
</html>`;
  },


  /*
   * frontchannelLogoutPendingSource
   *
   * description: HTML source rendered when there are pending front-channel logout iframes to be
   *   called to trigger RP logouts. It should handle waiting for the frames to be loaded as well
   *   as have a timeout mechanism in it.
   * affects: session management
   */
  async frontchannelLogoutPendingSource(ctx, frames, postLogoutRedirectUri, timeout) {
    changeme('frontchannelLogoutPendingSource', 'customize the front-channel logout pending page');
    ctx.body = `<!DOCTYPE html>
<head>
  <title>Logout</title>
  <style>
    iframe {
      visibility: hidden;
      position: absolute;
      left: 0;
      top: 0;
      height:0;
      width:0;
      border: none;
    }
  </style>
</head>
<body>
  ${frames.join('')}
  <script>
    var loaded = 0;
    function redirect() {
      window.location.replace("${postLogoutRedirectUri}");
    }
    function frameOnLoad() {
      loaded += 1;
      if (loaded === ${frames.length}) redirect();
    }
    Array.prototype.slice.call(document.querySelectorAll('iframe')).forEach(function (element) {
      element.onload = frameOnLoad;
    });
    setTimeout(redirect, ${timeout});
  </script>
</body>
</html>`;
  },


  /*
   * uniqueness
   *
   * description: Function resolving whether a given value with expiration is presented first time
   * affects: client_secret_jwt and private_key_jwt client authentications
   */
  async uniqueness(ctx, jti, expiresAt) {
    changeme('uniqueness', 'to have the values unique-checked across processes');
    if (cache.get(jti)) return false;

    cache.set(jti, true, (expiresAt - epochTime()) * 1000);

    return true;
  },


  /*
   * renderError
   *
   * description: Helper used by the OP to present errors which are not meant to be 'forwarded' to
   *   the RP's redirect_uri
   * affects: presentation of errors encountered during authorization
   */
  async renderError(ctx, error) {
    changeme('renderError', 'customize the look of the error page');
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


  /*
   * interactionUrl
   *
   * description: Helper used by the OP to determine where to redirect User-Agent for necessary
   *   interaction, can return both absolute and relative urls
   * affects: authorization interactions
   */
  async interactionUrl(ctx, interaction) { // eslint-disable-line no-unused-vars
    changeme('interactionUrl', 'to specify where the user interactions should take place');
    return `/interaction/${ctx.oidc.uuid}`;
  },

  /*
   * interactionCheck
   *
   * description: Helper used by the OP as a final check whether the End-User should be sent to
   *   interaction or not, the default behavior is that every RP must be authorized per session and
   *   that native application clients always require End-User prompt to be confirmed. return false
   *   if no interaction should be performed, return an object with relevant error, reason, etc.
   *   when interaction should be requested
   * affects: authorization interactions
   */
  async interactionCheck(ctx) {
    changeme('interactionCheck', 'to define the policy for requiring End-User interactions');
    if (!ctx.oidc.session.sidFor(ctx.oidc.client.clientId)) {
      return {
        error: 'consent_required',
        error_description: 'client not authorized for End-User session yet',
        reason: 'client_not_authorized',
      };
    } else if (ctx.oidc.client.applicationType === 'native' && ctx.oidc.params.response_type !== 'none' && ctx._matchedRouteName !== 'resume') {
      return {
        error: 'interaction_required',
        error_description: 'native clients require End-User interaction',
        reason: 'native_client_prompt',
      };
    }

    return false;
  },


  /*
   * audiences
   *
   * description: Helper used by the OP to push additional audiences to issued ID Tokens and other
   *   signed responses. The return value should either be falsy to omit adding additional audiences
   *   or an array of strings to push.
   * affects: id token audiences, signed userinfo audiences
   */
  async audiences(ctx, id, token) { // eslint-disable-line no-unused-vars
    // token is a reference to the token used for which a given account is being loaded,
    // is undefined in scenarios where claims are returned from authorization endpoint
    return undefined;
  },


  /*
   * findById
   *
   * description: Helper used by the OP to load your account and retrieve it's available claims. The
   *   return value should be a Promise and #claims() can return a Promise too
   * affects: authorization, authorization_code and refresh_token grants, id token claims
   */
  async findById(ctx, id, token) { // eslint-disable-line no-unused-vars
    // token is a reference to the token used for which a given account is being loaded,
    // is undefined in scenarios where claims are returned from authorization endpoint
    changeme('findById', 'to use your own account model');
    return {
      accountId: id,
      async claims() { return { sub: id }; },
    };
  },

  /*
   * unsupported
   *
   * description: Fine-tune the algorithms your provider should support by further omitting values
   *   from the respective discovery properties
   * affects: signing, encryption, discovery, client validation
   */
  unsupported: {
    idTokenEncryptionAlgValues: [],
    idTokenEncryptionEncValues: [],
    idTokenSigningAlgValues: [],
    requestObjectEncryptionAlgValues: [],
    requestObjectEncryptionEncValues: [],
    requestObjectSigningAlgValues: [],
    tokenEndpointAuthSigningAlgValues: [],
    introspectionEndpointAuthSigningAlgValues: [],
    revocationEndpointAuthSigningAlgValues: [],
    userinfoEncryptionAlgValues: [],
    userinfoEncryptionEncValues: [],
    userinfoSigningAlgValues: [],
  },


  /*
   * refreshTokenRotation
   *
   * description: Configures if and how the OP rotates refresh tokens after they are used
   * affects: refresh token rotation and adjacent revocation
   */

  // TODO:
  // * supported values:
  // *    'none' - refresh tokens are not rotated and their initial expiration date is final
  // *    'rotateAndConsume' - refresh tokens are rotated when used, current token is marked as
  // *                         consumed and new one is issued with new TTL, when a consumed refresh
  // *                         token is encountered an error is returned instead and the whole token
  // *                         chain (grant) is revoked.
  refreshTokenRotation: 'rotateAndConsume',
};

/*
 * introspectionEndpointAuthMethods
 *
 * description: List of Client Authentication methods supported by this OP's Introspection Endpoint
 * affects: discovery, client authentication for introspection, registration and registration
 * management
 */
DEFAULTS.introspectionEndpointAuthMethods = DEFAULTS.tokenEndpointAuthMethods;
/*
 * revocationEndpointAuthMethods
 *
 * description: List of Client Authentication methods supported by this OP's Revocation Endpoint
 * affects: discovery, client authentication for revocation, registration and registration
 * management
 */
DEFAULTS.revocationEndpointAuthMethods = DEFAULTS.tokenEndpointAuthMethods;

module.exports = DEFAULTS;
