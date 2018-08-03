const LRU = require('lru-cache');

const attention = require('./attention');
const epochTime = require('./epoch_time');

const cache = new LRU(100);

const warned = new Set();
function changeme(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    attention.info(`default helper ${name} called, you should probably change it in order to ${msg}.`);
  }
}

const DEFAULTS = {


  /*
   * acrValues
   *
   * description: Array of strings, the Authentication Context Class References that OP supports.
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
    acr: null, sid: null, auth_time: null, iss: null, openid: ['sub'],
  },


  /*
   * clientCacheDuration
   *
   * description: A `Number` value (in seconds) describing how long a dynamically loaded client
   *    should remain cached.
   * affects: adapter-backed client cache duration
   * recommendation: do not set to a low value or completely disable this, client properties are
   *   validated upon loading up and this may be potentially an expensive operation, sometimes even
   *   requesting resources from the network (i.e. client jwks_uri, sector_identifier_uri etc).
   */
  clientCacheDuration: Infinity,


  /*
   * clockTolerance
   *
   * description: A `Number` value (in seconds) describing the allowed system clock skew
   * affects: JWT (ID token, client assertion) and Token expiration validations
   * recommendation: Set to a reasonable value (60) to cover server-side client and oidc-provider
   *   server clock skew
   */
  clockTolerance: 0,


  /*
   * cookies
   *
   * description: Options for the [cookie module][module-cookies]
   *   used by the OP to keep track of various User-Agent states.
   * affects: User-Agent sessions, passing of authorization details to interaction
   * @nodefault
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
     * recommendation: set cookies.keys and cookies.long.signed = true
     */
    long: {
      secure: undefined,
      signed: undefined,
      httpOnly: true, // cookies are not readable by client-side javascript
      maxAge: (14 * 24 * 60 * 60) * 1000, // 14 days in ms
    },

    /*
     * cookies.short
     *
     * description: Options for short-term cookies
     * affects: passing of authorization details to interaction
     * recommendation: set cookies.keys and cookies.short.signed = true
     */
    short: {
      secure: undefined,
      signed: undefined,
      httpOnly: true, // cookies are not readable by client-side javascript
      maxAge: (10 * 60) * 1000, // 10 minutes in ms
    },

    /*
     * cookies.keys
     *
     * description: [Keygrip][keygrip-module] Signing keys used for cookie
     *   signing to prevent tampering.
     * recommendation: Rotate regularly (by prepending new keys) with a reasonable interval and keep
     *   a reasonable history of keys to allow for returning user session cookies to still be valid
     *   and re-signed
     */
    keys: [],

    /*
     * cookies.thirdPartyCheckUrl
     *
     * description: URL for 3rd party cookies support check helper
     * affects: sessionManagement feature
     *
     */
    thirdPartyCheckUrl: 'https://cdn.rawgit.com/panva/3rdpartycookiecheck/92fead3f/start.html', // TODO: move under sessionManagement in next major
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
   *   recognised by the authorization and device authorization endpoints. These parameters are then
   *   available in `ctx.oidc.params` as well as passed to interaction session details
   * affects: authorization, device_authorization, interaction
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

    alwaysIssueRefresh: false,
    backchannelLogout: false,
    claimsParameter: false,
    clientCredentials: false,
    conformIdTokenClaims: false, // TODO: true in next major
    deviceCode: false,
    encryption: false,
    frontchannelLogout: false,
    introspection: false,
    jwtIntrospection: false,
    registration: false,
    registrationManagement: false,
    request: false,
    revocation: false,
    sessionManagement: false,
    webMessageResponseMode: false,
  },

  /*
   * formats
   *
   * description: This option allows to configure the token storage and value formats. The different
   *   values change how a token value is generated as well as what properties get sent to the
   *   adapter for storage. Three formats are defined, see the expected
   *   [Adapter API](/example/my_adapter.js) for each format's specifics.
   *
   *   - `legacy` is the current and default format until next major release. no changes in the
   *     format sent to adapter.
   *   - `opaque` formatted tokens have a different value then `legacy` and in addition store what
   *     was in legacy format encoded under `payload` as root properties, this makes analysing the
   *     data in your storage way easier
   *   - `jwt` formatted tokens are issued as JWTs and stored the same as `opaque` only with
   *     additional property `jwt`. The signing algorithm for these tokens uses the client's
   *     `id_token_signed_response_alg` value and falls back to `RS256` for tokens with no relation
   *     to a client or when the client's alg is `none`
   * affects: properties passed to adapters for token types, issued token formats
   * recommendation: set default to `opaque` if you're still developing your application, `legacy`
   *   will not be the default in the major versions coming forward. It is not recommended to set
   *   `jwt` as default, if you need it, it's most likely just for Access Tokens.
   */
  formats: {
    default: 'legacy',

    AccessToken: undefined,
    AuthorizationCode: undefined,
    RefreshToken: undefined,
    DeviceCode: undefined,
    ClientCredentials: undefined,
    InitialAccessToken: undefined,
    RegistrationAccessToken: undefined,
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
   * description: Routing values used by the OP. Only provide routes starting with "/"
   * affects: routing
   */
  routes: {
    authorization: '/auth',
    certificates: '/certs',
    check_session: '/session/check',
    device_authorization: '/device/auth',
    end_session: '/session/end',
    introspection: '/token/introspection',
    registration: '/reg',
    revocation: '/token/revocation',
    token: '/token',
    userinfo: '/me',
    code_verification: '/device',
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
   * description: List of the Subject Identifier types that this OP supports. Valid types are
   *   - `public`
   *   - `pairwise`
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
  // TODO: pairwise helper instead, might do salting, might do random generation and mapping
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
    DeviceCode: 10 * 60, // 10 minutes in seconds
    IdToken: 60 * 60, // 1 hour in seconds
    RefreshToken: 14 * 24 * 60 * 60, // 14 days in seconds
  },


  /*
   * extraClientMetadata
   *
   * description: Allows for custom client metadata to be defined, validated, manipulated as well as
   *   for existing property validations to be extended
   * affects: clients, registration, registration management
   * @nodefault
   */
  extraClientMetadata: {
    /*
     * extraClientMetadata.properties
     *
     * description: Array of property names that clients will be allowed to have defined. Property
     *   names will have to strictly follow the ones defined here. However, on a Client instance
     *   property names will be snakeCased.
     */
    properties: [],
    /*
     * extraClientMetadata.validator
     *
     * description: validator function that will be executed in order once for every property
     *   defined in `extraClientMetadata.properties`, regardless of its value or presence on the
     *   client metadata passed in. Must be synchronous, async validators or functions returning
     *   Promise will be rejected during runtime. To modify the current client metadata values (for
     *   current key or any other) just modify the passed in `metadata` argument.
     */
    validator(key, value, metadata) { // eslint-disable-line no-unused-vars
      // validations for key, value, other related metadata

      // throw new Provider.errors.InvalidClientMetadata() to reject the client metadata (see all
      //   errors on Provider.errors)

      // metadata[key] = value; to assign values

      // return not necessary, metadata is already a reference.
    },
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
   * description: HTML source rendered when when session management feature renders a confirmation
   *   prompt for the User-Agent.
   * affects: session management
   */
  async logoutSource(ctx, form) {
    // @param ctx - koa request context
    // @param form - form source (id="op.logoutForm") to be embedded in the page and submitted by
    //   the End-User
    changeme('logoutSource', 'customize the look of the logout page');
    ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>Logout Request</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
  @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);button,h1{text-align:center}h1{font-weight:100;font-size:1.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}button{font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;width:100%;display:block;margin-bottom:10px;position:relative;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}
  </style>
</head>
<body>
  <div class="container">
    <h1>Do you want to sign-out from ${ctx.host}?</h1>
    <script>
      function logout() {
        var form = document.getElementById('op.logoutForm');
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'logout';
        input.value = 'yes';
        form.appendChild(input);
        form.submit();
      }
      function rpLogoutOnly() {
        var form = document.getElementById('op.logoutForm');
        form.submit();
      }
    </script>
    ${form}
    <button onclick="logout()">Yes, sign me out</button>
    <button onclick="rpLogoutOnly()">No, stay signed in</button>
  </div>
</body>
</html>`;
  },


  /*
   * userCodeInputSource
   *
   * description: HTML source rendered when device code feature renders an input prompt for the
   *   User-Agent.
   * affects: device code input
   */
  async userCodeInputSource(ctx, form, out, err) {
    // @param ctx - koa request context
    // @param form - form source (id="op.deviceInputForm") to be embedded in the page and submitted
    //   by the End-User.
    // @param out - if an error is returned the out object contains details that are fit to be
    //   rendered, i.e. does not include internal error messages
    // @param err - error object with an optional userCode property passed when the form is being
    //   re-rendered due to code missing/invalid/expired
    changeme('userCodeInputSource', 'customize the look of the user code input page');
    let msg;
    if (err && (err.userCode || err.name === 'NoCodeError')) {
      msg = '<p class="red">The code you entered is incorrect. Try again</p>';
    } else if (err) {
      msg = '<p class="red">There was an error processing your request</p>';
    } else {
      msg = '<p>Enter the code displayed on your device</p>';
    }
    ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>Sign-in</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
    @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}p.red{color:#d50000}input[type=email],input[type=password],input[type=text]{height:44px;font-size:16px;width:100%;margin-bottom:10px;-webkit-appearance:none;background:#fff;border:1px solid #d9d9d9;border-top:1px solid silver;padding:0 8px;box-sizing:border-box;-moz-box-sizing:border-box}[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative;text-align:center;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}[type=submit]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}
  </style>
</head>
<body>
  <div class="container">
    <h1>Sign-in</h1>
    ${msg}
    ${form}
    <button type="submit" form="op.deviceInputForm">Continue</button>
  </div>
</body>
</html>`;
  },


  /*
   * userCodeConfirmSource
   *
   * description: HTML source rendered when device code feature renders an a confirmation prompt for
   *   ther User-Agent.
   * affects: device code authorization confirmation
   */
  async userCodeConfirmSource(ctx, form, client, deviceInfo) {
    // @param ctx - koa request context
    // @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
    //   submitted by the End-User.
    // @param deviceInfo - device information from the device_authorization_endpoint call
    changeme('userCodeConfirmSource', 'customize the look of the user code confirmation page');
    const {
      clientId, clientName, clientUri, logoUri, policyUri, tosUri, // eslint-disable-line no-unused-vars, max-len
    } = ctx.oidc.client;
    ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>Device Login Confirmation</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
    @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);.help,h1,h1+p{text-align:center}h1,h1+p{font-weight:100}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}a{text-decoration:none;color:#666;font-weight:400;display:inline-block;opacity:.6}.help{width:100%;font-size:12px}
  </style>
</head>
<body>
  <div class="container">
    <h1>Confirm Device</h1>
    <p>
      You are about to authorize a <code>${clientName || clientId}</code> device client on IP <code>${deviceInfo.ip}</code>, identified by <code>${deviceInfo.userAgent}</code>
      <br/><br/>
      If you did not initiate this action and/or are unaware of such device in your possession please close this window.
    </p>
    ${form}
    <button autofocus type="submit" form="op.deviceConfirmForm">Continue</button>
    <div class="help">
      <a href="">[ Cancel ]</a>
    </div>
  </div>
</body>
</html>`;
  },


  /*
   * deviceCodeSuccess
   *
   * description: HTML source rendered when device code feature renders a success page for the
   *   User-Agent.
   * affects: device code success page
   */
  async deviceCodeSuccess(ctx) {
    // @param ctx - koa request context
    changeme('deviceCodeSuccess', 'customize the look of the device code success page');
    const {
      clientId, clientName, clientUri, initiateLoginUri, logoUri, policyUri, tosUri, // eslint-disable-line no-unused-vars, max-len
    } = ctx.oidc.client;
    ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>Sign-in Success</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
    @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}
  </style>
</head>
<body>
  <div class="container">
    <h1>Sign-in Success</h1>
    <p>Your login ${clientName ? `with ${clientName}` : ''} was successful, you can now close this page.</p>
  </div>
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
  // TODO: check escaping of client entered url values
  async frontchannelLogoutPendingSource(ctx, frames, postLogoutRedirectUri, timeout) {
    changeme('frontchannelLogoutPendingSource', 'customize the front-channel logout pending page');
    ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>Logout</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
    iframe{visibility:hidden;position:absolute;left:0;top:0;height:0;width:0;border:none}
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
   * recommendation: configure this option to use a shared store if client_secret_jwt and
   *   private_key_jwt are used
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
   * description: Helper used by the OP to present errors to the User-Agent
   * affects: presentation of errors encountered during End-User flows
   */
  async renderError(ctx, out, error) { // eslint-disable-line no-unused-vars
    changeme('renderError', 'customize the look of the error page');
    ctx.type = 'html';
    ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>oops! something went wrong</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
    @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1{font-weight:100;text-align:center;font-size:2.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}pre{white-space:pre-wrap;white-space:-moz-pre-wrap;white-space:-pre-wrap;white-space:-o-pre-wrap;word-wrap:break-word;margin:0 0 0 1em;text-indent:-1em}
  </style>
</head>
<body>
  <div class="container">
    <h1>oops! something went wrong</h1>
    ${Object.entries(out).map(([key, value]) => `<pre><strong>${key}</strong>: ${value}</pre>`).join('')}
  </div>
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
    } if (
      ctx.oidc.client.applicationType === 'native'
      && ctx.oidc.params.response_type !== 'none'
      && !ctx.oidc.result) {
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
   * description: Helper used by the OP to push additional audiences to issued ID, Access and
   *   ClientCredentials Tokens as well as other signed responses. The return value should either be
   *   falsy to omit adding additional audiences or an array of strings to push.
   * affects: ID Token audiences, access token audiences, client credential audiences, signed
   *   UserInfo audiences
   */
  async audiences(ctx, sub, token, use, scope) { // eslint-disable-line no-unused-vars
    // @param ctx   - koa request context
    // @param sub   - account identifier (subject)
    // @param token - a reference to the token used for which a given account is being loaded,
    //   is undefined in scenarios where claims are returned from authorization endpoint
    // @param use   - can be one of "id_token", "userinfo", "access_token" depending on where the
    //   specific audiences are intended to be put in
    // @param scope - scope from either the request or related token
    return undefined;
  },


  /*
   * findById
   *
   * description: Helper used by the OP to load an account and retrieve its available claims. The
   *   return value should be a Promise and #claims() can return a Promise too
   * affects: authorization, authorization_code and refresh_token grants, ID Token claims
   */
  async findById(ctx, sub, token) { // eslint-disable-line no-unused-vars
    // @param ctx   - koa request context
    // @param sub   - account identifier (subject)
    // @param token - is a reference to the token used for which a given account is being loaded,
    //   is undefined in scenarios where claims are returned from authorization endpoint
    changeme('findById', 'to use your own account model');
    return {
      accountId: sub, // TODO: sub property in the future
      // @param use   - can either be "id_token" or "userinfo", depending on
      //   where the specific claims are intended to be put in
      // @param scope - the intended scope, while oidc-provider will mask
      //   claims depending on the scope automatically you might want to skip
      //   loading some claims from external resources etc. based on this detail
      //   or not return them in ID Tokens but only UserInfo and so on
      async claims(use, scope) { // eslint-disable-line no-unused-vars
        return { sub };
      },
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
    introspectionEncryptionAlgValues: [],
    introspectionEncryptionEncValues: [],
    introspectionSigningAlgValues: [],
  },


  /*
   * refreshTokenRotation
   *
   * description: Configures if and how the OP rotates refresh tokens after they are used. Supported
   *   values are
   *   - `none` refresh tokens are not rotated and their initial expiration date is final
   *   - `rotateAndConsume` when refresh tokens are rotated when used, current token is marked as
   *     consumed and new one is issued with new TTL, when a consumed refresh token is
   *     encountered an error is returned instead and the whole token chain (grant) is revoked
   * affects: refresh token rotation and adjacent revocation
   */
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
