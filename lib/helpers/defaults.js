/* eslint-disable max-len */

const crypto = require('crypto');
const os = require('os');

const LRU = require('lru-cache');

const attention = require('./attention');
const epochTime = require('./epoch_time');

const cache = new LRU(100);

const warned = new Set();
function shouldChange(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    attention.info(`default helper ${name} called, you SHOULD change it in order to ${msg}.`);
  }
}
function mustChange(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    attention.warn(`default helper ${name} called, you MUST change it in order to ${msg}.`);
  }
}

const DEFAULTS = {


  /*
   * acrValues
   *
   * description: Array of strings, the Authentication Context Class References that OP supports.
   * affects: discovery, ID Token acr claim values
   *
   * example: FAQ: return acr/amr from session
   * To return the acr and/or amr from the established session rather then values from
   * a this given authorization request overload the OIDCContext.
   *
   * ```js
   * Object.defineProperties(provider.OIDCContext.prototype, {
   *   acr: { get() { return this.session.acr; } },
   *   amr: { get() { return this.session.amr; } },
   * });
   * ```
   */
  acrValues: [],


  /*
   * claims
   *
   * description: Array of the Claim Names of the Claims that the OpenID Provider MAY be able to
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
   * description: Options for the [cookie module](https://github.com/pillarjs/cookies#cookiesset-name--value---options--)
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
   * description: Pass an iterable object (i.e. array or Set of strings) to extend the parameters
   *   recognised by the authorization and device authorization endpoints. These parameters are then
   *   available in `ctx.oidc.params` as well as passed to interaction session details
   * affects: authorization, device_authorization, interaction
   */
  extraParams: [],


  /*
   * features
   *
   * description: Enable/disable features.
   */
  features: {
    /*
     * features.devInteractions
     *
     * description: Development-ONLY out of the box interaction views bundled with the library allow
     * you to skip the boring frontend part while experimenting with oidc-provider. Enter any
     * username (will be used as sub claim value) and any password to proceed.
     *
     * Be sure to disable and replace this feature with your actual frontend flows and End-User
     * authentication flows as soon as possible. These views are not meant to ever be seen by actual
     * users.
     */
    devInteractions: true,

    /*
     * features.discovery
     *
     * title: [Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
     *
     * description: Exposes `/.well-known/webfinger` and `/.well-known/openid-configuration`
     * endpoints. Contents of the latter reflect your actual configuration, i.e. available claims,
     * features and so on.
     *
     * WebFinger always returns positive results and links to this issuer, it is not resolving the
     * resources in any way.
     */
    discovery: true,

    /*
     * features.requestUri
     *
     * title: [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2) - Passing a Request Object by Reference
     *
     * description: Enables the use and validations of `request_uri` parameter
     *
     * example: To disable request_uri pre-registration
     * Configure `features.requestUri` with an object like so instead of a Boolean value.
     *
     * ```js
     * { requireRequestUriRegistration: false }
     * ```
     */
    requestUri: true,

    /*
     * features.oauthNativeApps
     *
     * title: [RFC8252](https://tools.ietf.org/html/rfc8252) - OAuth 2.0 Native Apps Best Current Practice
     * description: Changes `redirect_uris` validations for clients with application_type `native`
     * to those defined in the RFC. If PKCE is not enabled it
     * will be force-enabled automatically.
     */
    oauthNativeApps: true,

    /*
     * features.pkce
     *
     * title: [RFC7636](https://tools.ietf.org/html/rfc7636) - Proof Key for Code Exchange by OAuth Public Clients
     *
     * description: Enables PKCE.
     *
     *
     * example: To force native clients to use PKCE
     * Configure `features.pkce` with an object like so instead of a Boolean value.
     *
     * ```js
     * { forcedForNative: true }
     * ```
     *
     * example: To fine-tune the supported code challenge methods
     * Configure `features.pkce` with an object like so instead of a Boolean value.
     *
     * ```js
     * { supportedMethods: ['plain', 'S256'] }
     * ```
     */
    pkce: true,

    /*
     * features.alwaysIssueRefresh
     *
     * description: To have your provider issue Refresh Tokens even if offline_access scope is not
     * requested.
     *
     * @skip
     *
     */
    alwaysIssueRefresh: false,

    /*
     * features.backchannelLogout
     *
     * title: [Back-Channel Logout 1.0 - draft 04](https://openid.net/specs/openid-connect-backchannel-1_0-04.html)
     *
     * description: Enables Back-Channel Logout features.
     *
     */
    backchannelLogout: false,

    /*
     * features.certificateBoundAccessTokens
     *
     * title: [draft-ietf-oauth-mtls-12](https://tools.ietf.org/html/draft-ietf-oauth-mtls-12) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens
     *
     * description: Enables Certificate Bound Access Tokens. Clients may be registered with
     * `tls_client_certificate_bound_access_tokens` to indicate intention to receive mutual TLS client
     *  certificate bound access tokens.

     * example: Setting up the environment for Certificate Bound Access Tokens
     * To enable Certificate Bound Access Tokens the provider expects your TLS-offloading proxy to
     * handle the client certificate validation, parsing, handling, etc. Once set up you are expected
     * to forward `x-ssl-client-cert` header with variable values set by this proxy. An important
     * aspect is to sanitize the inbound request headers at the proxy.
     *
     * <br/><br/>
     *
     * The most common openssl based proxies are Apache and NGINX, with those you're looking to use
     *
     * <br/><br/>
     *
     * __`SSLVerifyClient` (Apache) / `ssl_verify_client` (NGINX)__ with the appropriate configuration
     * value that matches your setup requirements.
     *
     * <br/><br/>
     *
     * Set the proxy request header with variable set as a result of enabling MTLS
     *
     * ```nginx
     * # NGINX
     * proxy_set_header x-ssl-client-cert $ssl_client_cert;
     * ```
     *
     * ```apache
     * # Apache
     * RequestHeader set x-ssl-client-cert  ""
     * RequestHeader set x-ssl-client-cert "%{SSL_CLIENT_CERT}s"
     * ```
     *
     * You should also consider hosting the endpoints supporting client authentication, on a separate
     * host name or port in order to prevent unintended impact on the TLS behaviour of your other
     * endpoints, e.g. discovery or the authorization endpoint and changing the discovery values
     * for them with a post-middleware.
     *
     * ```js
     * provider.use(async (ctx, next) => {
     *   await next();
     *   if (ctx.oidc.route === 'discovery' && ctx.method === 'GET' && ctx.status === 200) {
     *     ctx.body.userinfo_endpoint = '...';
     *     ctx.body.token_endpoint = '...';
     *   }
     * });
     * ```
     *
     * When doing that be sure to remove the client
     * provided headers of the same name on the non-MTLS enabled host name / port in your proxy setup
     * or block the routes for these there completely.
     *
     */
    certificateBoundAccessTokens: false,

    /*
     * features.claimsParameter
     *
     * title: [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.5) - Requesting Claims using the "claims" Request Parameter
     *
     * description: Enables the use and validations of `claims` parameter as described in the
     * specification.
     *
     */
    claimsParameter: false,

    /*
     * features.clientCredentials
     *
     * title: [RFC6749](https://tools.ietf.org/html/rfc6749#section-1.3.4) - Client Credentials
     *
     * description: Enables `grant_type=client_credentials` to be used on the token endpoint.
     */
    clientCredentials: false,

    /*
     * features.conformIdTokenClaims
     *
     * title: ID Token only contains End-User claims when response_type=id_token
     *
     * description: [Core 1.0 - 5.4. Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.4)
     * defines that claims requested using the `scope` parameter are only returned from the UserInfo
     * Endpoint unless the `response_type` is `id_token`.
     *
     * The conform/non-conform behaviour results are like so:
     *
     * | flag value | request params | authorization_endpoint ID Token (if issued) | token_endpoint ID Token (if issued) |
     * |---|---|---|---|
     * | false | `response_type=` _any_<br/><br/> `scope=openid email` | ✅ `sub`<br/> ✅ `email`<br/> ✅ `email_verified` | ✅ `sub`<br/> ✅ `email`<br/> ✅ `email_verified` |
     * | true | `response_type=` _any but_ `id_token`<br/><br/> `scope=openid email` | ✅ `sub`<br/> ❌ `email`<br/> ❌ `email_verified` | ✅ `sub`<br/> ❌ `email`<br/> ❌ `email_verified` |
     * | true | `response_type=` _any but_ `id_token`<br/><br/> `scope=openid email`<br/><br/> `claims={"id_token":{"email":null}}` | ✅ `sub`<br/> ✅ `email`<br/> ❌ `email_verified` | ✅ `sub`<br/> ✅ `email`<br/> ❌ `email_verified` |
     * | true | `response_type=id_token`<br/><br/> `scope=openid email` | ✅ `sub`<br/> ✅ `email`<br/> ✅ `email_verified` | _n/a_ |
     *
     * @skip
     *
     */
    conformIdTokenClaims: true,

    /*
     * features.deviceFlow
     *
     * title: [draft-ietf-oauth-device-flow-12](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-12) - Device Flow for Browserless and Input Constrained Devices
     *
     * description: Enables Device Flow features
     */
    deviceFlow: false,

    /*
     * features.encryption
     *
     * description: Enables encryption features such as receiving encrypted UserInfo responses,
     * encrypted ID Tokens and allow receiving encrypted Request Objects.
     */
    encryption: false,

    /*
     * features.frontchannelLogout
     *
     * title: [Front-Channel Logout 1.0 - draft 02](https://openid.net/specs/openid-connect-frontchannel-1_0-02.html)
     *
     * description: Enables Front-Channel Logout features
     */
    frontchannelLogout: false,

    /*
     * features.introspection
     *
     * title: [RFC7662](https://tools.ietf.org/html/rfc7662) - OAuth 2.0 Token Introspection
     *
     * description: Enables Token Introspection features
     *
     */
    introspection: false,

    /*
     * features.jwtIntrospection
     *
     * title: [draft-ietf-oauth-jwt-introspection-response-00](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-00) - JWT Response for OAuth Token Introspection
     *
     * description: Enables JWT responses for Token Introspection features
     *
     */
    jwtIntrospection: false,


    /*
     * features.jwtResponseModes
     *
     * title: [openid-financial-api-jarm-wd-01](https://openid.net/specs/openid-financial-api-jarm-wd-01.html) - JWT Secured Authorization Response Mode (JARM)
     *
     * description: Enables JWT Secured Authorization Responses
     *
     */
    jwtResponseModes: false,

    /*
     * features.registration
     *
     * title: [Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
     *
     * description: Enables Dynamic Client Registration, by default with no Initial Access Token.
     *
     * example: To enable a fixed Initial Access Token for the registration POST call
     * Configure `features.registration` to be an object like so:
     *
     * ```js
     * { initialAccessToken: 'tokenValue' }
     * ```
     *
     * example: To provide your own client_id value generator:
     * ```js
     * { idFactory: () => randomValue() }
     * ```
     *
     * example: To provide your own client_secret value generator:
     * ```js
     * { secretFactory: () => randomValue() }
     * ```
     *
     * example: To enable a Initial Access Token lookup from your Adapter's store
     * Configure `features.registration` to be an object like so:
     *
     * ```js
     * { initialAccessToken: true }
     * ```
     *
     * example: To add an Initial Access Token and retrive its value
     *
     * ```js
     * new (provider.InitialAccessToken)({}).save().then(console.log);
     * ```
     *
     * example: To define registration and registration management policies
     * Policies are sync/async functions that are assigned to an Initial Access Token that run
     * before the regular client property validations are run. Multiple policies may be assigned
     * to an Initial Access Token and by default the same policies will transfer over to the
     * Registration Access Token.
     *
     * A policy may throw / reject and it may modify the properties object.
     *
     * To define policy functions configure `features.registration` to be an object like so:
     * ```js
     * {
     *   initialAccessToken: true, // to enable adapter-backed initial access tokens
     *   policies: {
     *     'my-policy': function (ctx, properties) {
     *       // @param ctx - koa request context
     *       // @param properties - the client properties which are about to be validated
     *
     *       // example of setting a default
     *       if (!('client_name' in properties)) {
     *         properties.client_name = generateRandomClientName();
     *       }
     *
     *       // example of forcing a value
     *       properties.userinfo_signed_response_alg = 'RS256';
     *
     *       // example of throwing a validation error
     *       if (someCondition(ctx, properties)) {
     *         throw new Provider.errors.InvalidClientMetadata('validation error message');
     *       }
     *     },
     *     'my-policy-2': async function (ctx, properties) {},
     *   },
     * }
     * ```
     *
     * An Initial Access Token with those policies being executed (one by one in that order) is
     * created like so
     * ```js
     * new (provider.InitialAccessToken)({ policies: ['my-policy', 'my-policy-2'] }).save().then(console.log);
     * ```
     *
     * Note: referenced policies must always be present when encountered on a token, an AssertionError
     * will be thrown inside the request context if it's not, resulting in a 500 Server Error.
     *
     * Note: the same policies will be assigned to the Registration Access Token after a successful
     * validation. If you wish to assign different policies to the Registration Access Token
     * ```js
     * // inside your final ran policy
     * ctx.oidc.entities.RegistrationAccessToken.policies = ['update-policy'];
     * ```
     */
    registration: false,

    /*
     * features.registrationManagement
     *
     * title: [OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)
     *
     * description: Enables Update and Delete features described in the RFC, by default with no
     * rotating Registration Access Token.
     *
     * example: To have your provider rotate the Registration Access Token with a successful update
     * Configure `features.registrationManagement` as an object like so:
     *
     * ```js
     * { rotateRegistrationAccessToken: true }
     * ```
     * The provider will discard the current Registration Access Token with a successful update and
     * issue a new one, returning it to the client with the Registration Update Response.
     */
    registrationManagement: false,

    /*
     * features.resourceIndicators
     *
     * title: [draft-ietf-oauth-resource-indicators-01](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-01) - Resource Indicators for OAuth 2.0
     *
     * description: Enables the use of `resource` parameter for the authorization and token
     *   endpoints. In order for the feature to be any useful you must also use the `audiences`
     *   helper function to validate the resource(s) and transform it to jwt's token audience.
     *
     * example: Example use
     * This example will
     * - throw based on an OP policy when unrecognized or unauthorized resources are requested
     * - transform resources to audience and push them down to the audience of access tokens
     * - take both, the parameter and previously granted resources into consideration
     *
     * ```js
     * // const { InvalidTarget } = Provider.errors;
     * // `resourceAllowedForClient` is the custom OP policy
     * // `transform` is mapping the resource values to actual aud values
     *
     * {
     *   // ...
     *   async function audiences(ctx, sub, token, use) {
     *     if (use === 'access_token') {
     *       const { oidc: { route, client, params: { resource: resourceParam } } } = ctx;
     *       let grantedResource;
     *       if (route === 'token') {
     *         const { oidc: { params: { grant_type } } } = ctx;
     *         switch (grant_type) {
     *           case 'authorization_code':
     *             grantedResource = ctx.oidc.entities.AuthorizationCode.resource;
     *             break;
     *           case 'refresh_token':
     *             grantedResource = ctx.oidc.entities.RefreshToken.resource;
     *             break;
     *           case 'urn:ietf:params:oauth:grant-type:device_code':
     *             grantedResource = ctx.oidc.entities.DeviceCode.resource;
     *             break;
     *           default:
     *         }
     *       }
     *
     *       const allowed = await resourceAllowedForClient(resourceParam, grantedResource, client);
     *       if (!allowed) {
     *         throw new InvalidResource('unauthorized "resource" requested');
     *       }
     *
     *       // => array of validated and transformed string audiences or undefined if no audiences
     *       //    are to be listed
     *       return transform(resourceParam, grantedResource);
     *     }
     *   },
     *   formats: {
     *     default: 'opaque',
     *     AccessToken(token) {
     *       if (Array.isArray(token.aud)) {
     *         return 'jwt';
     *       }
     *
     *       return 'opaque';
     *     }
     *   },
     *   // ...
     * }
     * ```
     */
    resourceIndicators: false,

    /*
     * features.request
     *
     * title: [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.1) - Passing a Request Object by Value
     *
     * description: Enables the use and validations of `request` parameter
     */
    request: false,

    /*
     * features.revocation
     *
     * title: [RFC7009](https://tools.ietf.org/html/rfc7009) - OAuth 2.0 Token Revocation
     *
     * description: Enables Token Revocation
     *
     */
    revocation: false,

    /*
     * features.sessionManagement
     *
     * title: [Session Management 1.0 - draft 28](https://openid.net/specs/openid-connect-session-1_0-28.html)
     *
     * description: Enables Session Management features.
     *
     * example: [RECOMMENDED] To avoid endless "changed" events when Third-Party Cookies are disabled
     * The User-Agent must allow access to the provider cookies from a third-party context when the
     * OP frame is embedded.
     *
     * oidc-provider can check if third-party cookie access is enabled using a CDN hosted
     * [iframe][third-party-cookies-git]. It is recommended to host these helper pages on your own
     * (on a different domain from the one you host oidc-provider on). Once hosted, set the
     * `features.sessionManagement.thirdPartyCheckUrl` to an absolute URL for the start page.
     * See [this][third-party-cookies-so] for more info.
     *
     * Note: This is still just a best-effort solution and is in no way bulletproof. Currently there's
     * no better way to check if access to third party cookies has been blocked or the cookies are just
     * missing. (Safari's ITP 2.0 Storage Access API also cannot be used)
     *
     * Configure `features.sessionManagement` as an object like so:
     *
     * ```js
     * { thirdPartyCheckUrl: 'https://your-location.example.com/start.html' },
     * ```
     *
     * example: To disable removing frame-ancestors from Content-Security-Policy and X-Frame-Options
     * Only do this if you know what you're doing either in a followup middleware or your app server,
     * otherwise you shouldn't have the need to touch this option.
     *
     * Configure `features.sessionManagement` as an object like so:
     * ```js
     * { keepHeaders: true }
     * ```
     */
    sessionManagement: false,

    /*
     * features.webMessageResponseMode
     *
     * title: [draft-sakimura-oauth-wmrm-00](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00) - OAuth 2.0 Web Message Response Mode
     *
     * description: Enables `web_message` response mode.
     *
     * Note: Although a general advise to use a `helmet` ([express](https://www.npmjs.com/package/helmet),
     * [koa](https://www.npmjs.com/package/koa-helmet)) it is especially advised for your interaction
     * views routes if Web Message Response Mode is available on your deployment.
     */
    webMessageResponseMode: false,
  },

  /*
   * formats
   *
   * description: This option allows to configure the token storage and value formats. The different
   *   values change how a token value is generated as well as what properties get sent to the
   *   adapter for storage. Multiple formats are defined, see the expected
   *   [Adapter API](/example/my_adapter.js) for each format's specifics.
   *   - `opaque` (default) formatted tokens store every property as a root property in your adapter
   *   - `jwt` formatted tokens are issued as JWTs and stored the same as `opaque` only with
   *     additional property `jwt`. The signing algorithm for these tokens uses the client's
   *     `id_token_signed_response_alg` value and falls back to `RS256` for tokens with no relation
   *     to a client or when the client's alg is `none`
   * affects: properties passed to adapters for token types, issued token formats
   * recommendation: It is not recommended to set `jwt` as default, if you need it, it's most likely
   *   just for Access Tokens.
   *
   * example: To enable JWT Access Tokens
   *
   * Configure `formats`:
   * ```js
   * { default: 'opaque', AccessToken: 'jwt' }
   * ```
   * example: To dynamically decide on the format used, e.g. if it is intended for more audiences
   *
   * Configure `formats`:
   * ```js
   * {
   *   default: 'opaque',
   *   AccessToken(token) {
   *     if (Array.isArray(token.aud)) {
   *       return 'jwt';
   *     }
   *
   *     return 'opaque';
   *   }
   * }
   * ```
   *
   * example: To enable the legacy format (only recommended for legacy deployments)
   * Configure `formats`:
   * ```js
   * { default: 'legacy' }
   * ```
   */
  formats: {
    default: 'opaque',

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
   * description: Array of the prompt values that the OpenID Provider MAY be able to resolve
   * affects: authorization
   */
  prompts: ['consent', 'login', 'none'],


  /*
   * responseTypes
   *
   * description: Array of response_type values that OP supports
   * affects: authorization, discovery, registration, registration management
   *
   * example: Supported values list
   * These are values defined in [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#Authentication)
   * and [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
   * ```js
   * [
   *   'code',
   *   'id_token', 'id_token token',
   *   'code id_token', 'code token', 'code id_token token',
   *   'none',
   * ]
   * ```
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
   * description: Array of the scope values that the OP supports
   * affects: discovery, authorization, ID Token claims, Userinfo claims
   */
  scopes: ['openid', 'offline_access'],


  /*
   * dynamicScopes
   *
   * description: Array of the dynamic scope values that the OP supports. These must be regular
   *   expressions that the OP will check string scope values, that aren't in the static list,
   *   against.
   * affects: discovery, authorization, ID Token claims, Userinfo claims
   *
   * example: Example: To enable a dynamic scope values like `write:{hex id}` and `read:{hex id}`
   * Configure `dynamicScopes` like so:
   *
   * ```js
   * [
   *   /^write:[a-fA-F0-9]{2,}$/,
   *   /^read:[a-fA-F0-9]{2,}$/,
   * ]
   * ```
   */
  dynamicScopes: [],


  /*
   * subjectTypes
   *
   * description: Array of the Subject Identifier types that this OP supports. Valid types are
   *   - `public`
   *   - `pairwise`
   * affects: discovery, registration, registration management, ID Token and Userinfo sub claim
   *   values
   */
  subjectTypes: ['public'],


  /*
   * pairwiseIdentifier
   *
   * description: Function used by the OP when resolving pairwise ID Token and Userinfo sub claim
   *   values. See [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.8.1)
   * affects: pairwise ID Token and Userinfo sub claim values
   * recommendation: Since this might be called several times in one request with the same arguments
   *   consider using memoization or otherwise caching the result based on account and client
   *   ids.
   */
  async pairwiseIdentifier(accountId, client) {
    mustChange('pairwiseIdentifier', 'provide an implementation for pairwise identifiers, the default one uses `os.hostname()` as salt and is therefore not fit for anything else than development');
    return crypto.createHash('sha256')
      .update(client.sectorIdentifier)
      .update(accountId)
      .update(os.hostname()) // put your own unique salt here, or implement other mechanism
      .digest('hex');
  },


  /*
   * tokenEndpointAuthMethods
   *
   * description: Array of Client Authentication methods supported by this OP's Token Endpoint
   * affects: discovery, client authentication for token endpoint, registration and
   * registration management
   * example: Supported values list
   * ```js
   * [
   *   'none',
   *   'client_secret_basic', 'client_secret_post',
   *   'client_secret_jwt', 'private_key_jwt',
   *   'tls_client_auth', 'self_signed_tls_client_auth',
   * ]
   * ```
   * example: Setting up the environment for tls_client_auth and self_signed_tls_client_auth
   * To enable MTLS based authentication methods the provider expects your TLS-offloading proxy to
   * handle the client certificate validation, parsing, handling, etc. Once set up you are expected
   * to forward `x-ssl-client-verify`, `x-ssl-client-s-dn` and `x-ssl-client-cert` headers with
   * variable values set by this proxy. An important aspect is to sanitize the inbound request
   * headers at the proxy.
   *
   * <br/><br/>
   *
   * The most common openssl based proxies are Apache and NGINX, with those you're looking to use
   *
   * <br/><br/>
   *
   * __`SSLVerifyClient` (Apache) / `ssl_verify_client` (NGINX)__ with the appropriate configuration
   * value that matches your setup requirements.
   *
   * <br/><br/>
   *
   * __`SSLCACertificateFile` or `SSLCACertificatePath` (Apache) / `ssl_client_certificate` (NGINX)__
   * with the values pointing to your accepted CA Certificates.
   *
   * <br/><br/>
   *
   * Set the proxy request headers with variables set as a result of enabling MTLS
   *
   * ```nginx
   * # NGINX
   * proxy_set_header x-ssl-client-cert $ssl_client_cert;
   * proxy_set_header x-ssl-client-verify $ssl_client_verify;
   * proxy_set_header x-ssl-client-s-dn $ssl_client_s_dn;
   * ```
   *
   * ```apache
   * # Apache
   * RequestHeader set x-ssl-client-cert  ""
   * RequestHeader set x-ssl-client-cert "%{SSL_CLIENT_CERT}s"
   * RequestHeader set x-ssl-client-verify  ""
   * RequestHeader set x-ssl-client-verify "%{SSL_CLIENT_VERIFY}s"
   * RequestHeader set x-ssl-client-s-dn  ""
   * RequestHeader set x-ssl-client-s-dn "%{SSL_CLIENT_S_DN}s"
   * ```
   *
   * You should also consider hosting the endpoints supporting client authentication, on a separate
   * host name or port in order to prevent unintended impact on the TLS behaviour of your other
   * endpoints, e.g. discovery or the authorization endpoint and changing the discovery values
   * for them with a post-middleware.
   *
   * ```js
   * provider.use(async (ctx, next) => {
   *   await next();
   *   if (ctx.oidc.route === 'discovery' && ctx.method === 'GET' && ctx.status === 200) {
   *     ctx.body.token_endpoint = '...';
   *     ctx.body.introspection_endpoint = '...';
   *     ctx.body.revocation_endpoint = '...';
   *   }
   * });
   * ```
   * When doing that be sure to remove the client
   * provided headers of the same name on the non-MTLS enabled host name / port in your proxy setup
   * or block the routes for these there completely.
   *
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
   * description: Expirations (in seconds, or dynamically returned value) for all token types
   * affects: tokens
   *
   * example: To resolve a ttl on runtime for each new token
   * Configure `ttl` for a given token type with a function like so, this must return a value, not a
   * Promise.
   *
   * ```js
   * {
   *   ttl: {
   *     AccessToken(token, client) {
   *       // return a Number (in seconds) for the given token (first argument), the associated client is
   *       // passed as a second argument
   *       // Tip: if the values are entirely client based memoize the results
   *       return resolveTTLfor(token, client);
   *     },
   *   },
   * }
   * ```
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
    shouldChange('postLogoutRedirectUri', 'specify where to redirect the user after logout without post_logout_redirect_uri specified or validated');
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
    shouldChange('logoutSource', 'customize the look of the logout page');
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
    shouldChange('userCodeInputSource', 'customize the look of the user code input page');
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
    shouldChange('userCodeConfirmSource', 'customize the look of the user code confirmation page');
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
   * deviceFlowSuccess
   *
   * description: HTML source rendered when device code feature renders a success page for the
   *   User-Agent.
   * affects: device code success page
   */
  async deviceFlowSuccess(ctx) {
    // @param ctx - koa request context
    shouldChange('deviceFlowSuccess', 'customize the look of the device code success page');
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
    shouldChange('frontchannelLogoutPendingSource', 'customize the front-channel logout pending page');
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
    mustChange('uniqueness', 'have the values unique-checked across processes');
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
    shouldChange('renderError', 'customize the look of the error page');
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
    shouldChange('interactionUrl', 'specify where the user interactions should take place');
    return `/interaction/${ctx.oidc.uuid}`;
  },

  /*
   * interactionCheck
   *
   * description: Helper used by the OP as a final check whether the End-User should be sent to
   *   interaction or not. return false if no interaction should be performed, return an object with
   *   relevant error, reason, etc. when interaction should be requested.
   *
   *   The default BCP behavior that is implemented, one that you SHOULD carry over to your own
   *   function should you choose to overwrite it, is that
   *
   *   - every client requires interaction the first time it's encountered in a session
   *   - native clients always require End-User prompt
   *   - consent is required every time when scopes or claims weren't accepted by the end-user yet
   *
   * affects: authorization interactions
   * example: when bypassing the BCP checks put forth by the default implementation
   *   You will have to do some of the actions an interaction resume would do automatically upon
   *   interaction success yourself, you would do these inside the interactionCheck helper.
   *
   *   - `ctx.oidc.session.sidFor(ctx.oidc.client.clientId, randomValue);`
   *   - `ctx.oidc.session.rejectedClaimsFor(ctx.oidc.client.clientId, rejectedClaims);`
   *   - `ctx.oidc.session.rejectedScopesFor(ctx.oidc.client.clientId, rejectedScopes);`
   *   - `ctx.oidc.session.promptedScopesFor(ctx.oidc.client.clientId, ctx.oidc.requestParamScopes);`
   *   - `ctx.oidc.session.promptedClaimsFor(ctx.oidc.client.clientId, ctx.oidc.requestParamClaims);`
   */
  async interactionCheck(ctx) {
    if (!ctx.oidc.session.sidFor(ctx.oidc.client.clientId)) {
      return {
        error: 'consent_required',
        error_description: 'client not authorized for End-User session yet',
        reason: 'client_not_authorized',
      };
    }

    if (
      ctx.oidc.client.applicationType === 'native'
      && ctx.oidc.params.response_type !== 'none'
      && !ctx.oidc.result) {
      return {
        error: 'interaction_required',
        error_description: 'native clients require End-User interaction',
        reason: 'native_client_prompt',
      };
    }

    const promptedScopes = ctx.oidc.session.promptedScopesFor(ctx.oidc.client.clientId);
    for (const scope of ctx.oidc.requestParamScopes) { // eslint-disable-line no-restricted-syntax
      if (!promptedScopes.has(scope)) {
        return {
          error: 'consent_required',
          error_description: 'requested scopes not granted by End-User',
          reason: 'scopes_missing',
        };
      }
    }

    const promptedClaims = ctx.oidc.session.promptedClaimsFor(ctx.oidc.client.clientId);
    for (const claim of ctx.oidc.requestParamClaims) { // eslint-disable-line no-restricted-syntax
      if (!promptedClaims.has(claim) && !['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim)) {
        return {
          error: 'consent_required',
          error_description: 'requested claims not granted by End-User',
          reason: 'claims_missing',
        };
      }
    }

    return false;
  },


  /*
   * audiences
   *
   * description: Helper used by the OP to push additional audiences to issued ID, Access and
   *   ClientCredentials Tokens as well as other signed responses (e.g. userinfo). The return value
   *   should either be falsy to omit adding additional audiences or an array of strings to push.
   * affects: ID Token audiences, access token audiences, client credential audiences, signed
   *   UserInfo audiences
   */
  async audiences(ctx, sub, token, use) { // eslint-disable-line no-unused-vars
    // @param ctx   - koa request context
    // @param sub   - account identifier (subject)
    // @param token - the token to which these additional audiences will be assed to. It is
    //   undefined when the audiences are pushed to a JWT userinfo response
    // @param use   - can be one of "id_token", "userinfo", "access_token" or "client_credentials"
    //   depending on where the specific audiences are intended to be put in
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
    // @param ctx - koa request context
    // @param sub {string} - account identifier (subject)
    // @param token - is a reference to the token used for which a given account is being loaded,
    //   is undefined in scenarios where claims are returned from authorization endpoint
    mustChange('findById', 'use your own account model');
    return {
      accountId: sub, // TODO: sub property in the future
      // @param use {string} - can either be "id_token" or "userinfo", depending on
      //   where the specific claims are intended to be put in
      // @param scope {string} - the intended scope, while oidc-provider will mask
      //   claims depending on the scope automatically you might want to skip
      //   loading some claims from external resources or through db projection etc. based on this
      //   detail or not return them in ID Tokens but only UserInfo and so on
      // @param claims {object} - the part of the claims authorization parameter for either
      //   "id_token" or "userinfo" (depends on the "use" param)
      // @param rejected {Array[String]} - claim names that were rejected by the end-user, you might
      //   want to skip loading some claims from external resources or through db projection
      async claims(use, scope, claims, rejected) { // eslint-disable-line no-unused-vars
        return { sub };
      },
    };
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


  /*
   * whitelistedJWA
   *
   * description: Fine-tune the algorithms your provider will support by declaring algorithm
   *   values for each respective JWA use
   * affects: signing, encryption, discovery, client validation
   * recommendation: Only allow JWA algs that are necessary. The current defaults are based on
   * recommendations from the [JWA specification](https://tools.ietf.org/html/rfc7518) + enables
   * RSASSA-PSS based on current guidance in FAPI. "none" JWT algs are disabled by default but
   * available if you need them.
   * @nodefault
   */
  whitelistedJWA: {

    /*
     * whitelistedJWA.tokenEndpointAuthSigningAlgValues
     *
     * description: JWA algorithms the provider supports on the token endpoint
     *
     * example: Supported values list
     * ```js
     * [
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    tokenEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.introspectionEndpointAuthSigningAlgValues
     *
     * description: JWA algorithms the provider supports on the introspection endpoint
     *
     * example: Supported values list
     * ```js
     * [
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    introspectionEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.revocationEndpointAuthSigningAlgValues
     *
     * description: JWA algorithms the provider supports on the revocation endpoint
     *
     * example: Supported values list
     * ```js
     * [
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    revocationEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.idTokenSigningAlgValues
     *
     * description: JWA algorithms the provider supports to sign ID Tokens with
     *
     * example: Supported values list
     * ```js
     * [
     *   'none',
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    idTokenSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.requestObjectSigningAlgValues
     *
     * description: JWA algorithms the provider supports to receive Request Objects with
     *
     * example: Supported values list
     * ```js
     * [
     *   'none',
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    requestObjectSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.userinfoSigningAlgValues
     *
     * description: JWA algorithms the provider supports to sign UserInfo responses with
     *
     * example: Supported values list
     * ```js
     * [
     *   'none',
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    userinfoSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.introspectionSigningAlgValues
     *
     * description: JWA algorithms the provider supports to sign JWT Introspection responses with
     *
     * example: Supported values list
     * ```js
     * [
     *   'none',
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    introspectionSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.authorizationSigningAlgValues
     *
     * description: JWA algorithms the provider supports to sign JWT Authorization Responses with
     *
     * example: Supported values list
     * ```js
     * [
     *   'HS256', 'HS384', 'HS512',
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     * ]
     * ```
     */
    authorizationSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256',
    ],


    /*
     * whitelistedJWA.idTokenEncryptionAlgValues
     *
     * description: JWA algorithms the provider supports to wrap keys for ID Token encryption
     *
     * example: Supported values list
     * ```js
     * [
     *   // asymmetric RSAES based
     *   'RSA-OAEP', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES
     *   'A128KW', 'A192KW', 'A256KW',
     *   // symmetric AES GCM based
     *   'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     * ]
     * ```
     */
    idTokenEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],


    /*
     * whitelistedJWA.requestObjectEncryptionAlgValues
     *
     * description: JWA algorithms the provider supports to receive encrypted Request Object keys
     * wrapped with
     *
     * example: Supported values list
     * ```js
     * [
     *   // asymmetric RSAES based
     *   'RSA-OAEP', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES
     *   'A128KW', 'A192KW', 'A256KW',
     *   // symmetric AES GCM based
     *   'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     * ]
     * ```
     */
    requestObjectEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],


    /*
     * whitelistedJWA.userinfoEncryptionAlgValues
     *
     * description: JWA algorithms the provider supports to wrap keys for UserInfo Response encryption
     *
     * example: Supported values list
     * ```js
     * [
     *   // asymmetric RSAES based
     *   'RSA-OAEP', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES
     *   'A128KW', 'A192KW', 'A256KW',
     *   // symmetric AES GCM based
     *   'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     * ]
     * ```
     */
    userinfoEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],


    /*
     * whitelistedJWA.introspectionEncryptionAlgValues
     *
     * description: JWA algorithms the provider supports to wrap keys for JWT Introspection response
     * encryption
     *
     * example: Supported values list
     * ```js
     * [
     *   // asymmetric RSAES based
     *   'RSA-OAEP', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES
     *   'A128KW', 'A192KW', 'A256KW',
     *   // symmetric AES GCM based
     *   'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     * ]
     * ```
     */
    introspectionEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],


    /*
     * whitelistedJWA.authorizationEncryptionAlgValues
     *
     * description: JWA algorithms the provider supports to wrap keys for JWT Authorization response
     * encryption
     *
     * example: Supported values list
     * ```js
     * [
     *   // asymmetric RSAES based
     *   'RSA-OAEP', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES
     *   'A128KW', 'A192KW', 'A256KW',
     *   // symmetric AES GCM based
     *   'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     * ]
     * ```
     */
    authorizationEncryptionAlgValues: [
      'A128KW', 'A256KW', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW', 'RSA-OAEP',
    ],


    /*
     * whitelistedJWA.idTokenEncryptionEncValues
     *
     * description: JWA algorithms the provider supports to encrypt ID Tokens with
     *
     * example: Supported values list
     * ```js
     * [
     *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
     * ]
     * ```
     */
    idTokenEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],


    /*
     * whitelistedJWA.requestObjectEncryptionEncValues
     *
     * description: JWA algorithms the provider supports decrypt Request Objects with
     * encryption
     *
     * example: Supported values list
     * ```js
     * [
     *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
     * ]
     * ```
     */
    requestObjectEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],


    /*
     * whitelistedJWA.userinfoEncryptionEncValues
     *
     * description: JWA algorithms the provider supports to encrypt UserInfo responses with
     *
     * example: Supported values list
     * ```js
     * [
     *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
     * ]
     * ```
     */
    userinfoEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],


    /*
     * whitelistedJWA.introspectionEncryptionEncValues
     *
     * description: JWA algorithms the provider supports to encrypt JWT Introspection responses with
     *
     * example: Supported values list
     * ```js
     * [
     *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
     * ]
     * ```
     */
    introspectionEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],


    /*
     * whitelistedJWA.authorizationEncryptionEncValues
     *
     * description: JWA algorithms the provider supports to encrypt JWT Authorization Responses with
     *
     * example: Supported values list
     * ```js
     * [
     *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
     * ]
     * ```
     */
    authorizationEncryptionEncValues: [
      'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
    ],
  },
};

/*
 * introspectionEndpointAuthMethods
 *
 * description: Array of Client Authentication methods supported by this OP's Introspection Endpoint.
 *   If no configuration value is provided the same values as for tokenEndpointAuthMethods will be
 *   used. Supported values list is the same as for tokenEndpointAuthMethods.
 * affects: discovery, client authentication for introspection, registration and registration
 * management
 */
DEFAULTS.introspectionEndpointAuthMethods = DEFAULTS.tokenEndpointAuthMethods;

/*
 * revocationEndpointAuthMethods
 *
 * description: Array of Client Authentication methods supported by this OP's Revocation Endpoint.
 *   If no configuration value is provided the same values as for tokenEndpointAuthMethods will be
 *   used. Supported values list is the same as for tokenEndpointAuthMethods.
 * affects: discovery, client authentication for revocation, registration and registration
 * management
 */
DEFAULTS.revocationEndpointAuthMethods = DEFAULTS.tokenEndpointAuthMethods;

module.exports = DEFAULTS;
