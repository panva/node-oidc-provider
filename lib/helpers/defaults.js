/* eslint-disable max-len */

const crypto = require('crypto');
const os = require('os');

const MemoryAdapter = require('../adapters/memory_adapter');
const { DEV_KEYSTORE } = require('../consts');

const runtimeSupport = require('./runtime_support');
const base64url = require('./base64url');
const attention = require('./attention');
const nanoid = require('./nanoid');
const { base: defaultPolicy } = require('./interaction_policy');
const htmlSafe = require('./html_safe');

const warned = new Set();
function shouldChange(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    attention.info(`default ${name} function called, you SHOULD change it in order to ${msg}.`);
  }
}
function mustChange(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    attention.warn(`default ${name} function called, you MUST change it in order to ${msg}.`);
  }
}

const DEFAULTS = {


  /*
   * acrValues
   *
   * description: Array of strings, the Authentication Context Class References that OP supports.
   */
  acrValues: [],


  /*
   * adapter
   *
   * description: The provided example and any new instance of oidc-provider will use the basic
   * in-memory adapter for storing issued tokens, codes, user sessions, dynamically registered
   * clients, etc. This is fine as long as you develop, configure and generally just play around
   * since every time you restart your process all information will be lost. As soon as you cannot
   * live with this limitation you will be required to provide your own custom adapter constructor
   * for oidc-provider to use. This constructor will be called for every model accessed the first
   * time it is needed.
   * The API oidc-provider expects is documented [here](/example/my_adapter.js).
   *
   * example: MongoDB adapter implementation
   *
   * See [/example/adapters/mongodb.js](/example/adapters/mongodb.js)
   *
   * example: Redis adapter implementation
   *
   * See [/example/adapters/redis.js](/example/adapters/redis.js)
   *
   * example: Redis w/ ReJSON adapter implementation
   *
   * See [/example/adapters/redis_rejson.js](/example/adapters/redis_rejson.js)
   *
   * example: Default in-memory adapter implementation
   *
   * See [/lib/adapters/memory_adapter.js](/lib/adapters/memory_adapter.js)
   *
   * @nodefault
   */
  adapter: MemoryAdapter,


  /*
   * claims
   *
   * description: Array of the Claim Names of the Claims that the OpenID Provider MAY be able to
   *   supply values for.
   */
  claims: {
    acr: null, sid: null, auth_time: null, iss: null, openid: ['sub'],
  },

  /*
   * clientBasedCORS
   *
   * description: Function used to check whether a given CORS request should be allowed
   *   based on the request's client.
   */
  clientBasedCORS(ctx, origin, client) { // eslint-disable-line no-unused-vars
    shouldChange('clientBasedCORS', 'control CORS allowed Origins based on the client making a CORS request');
    return true;
  },

  /*
   * clients
   *
   * description: Array of objects representing client metadata. These clients are referred to as
   * static, they don't expire, never reload, are always available. If the client metadata in this
   * array is invalid the Provider instantiation will fail with an error. In addition to these
   * clients the provider will use your adapter's `find` method when a non-cached client_id is
   * encountered. If you only wish to support statically configured clients and
   * no dynamic registration then make it so that your adapter resolves client find calls with a
   * falsy value (e.g. `return Promise.resolve()`) and don't take unnecessary DB trips.
   *
   * Client's metadata is validated as defined by the respective specification they've been defined
   * in.
   *
   * example: Available Metadata
   *
   * application_type, client_id, client_name, client_secret, client_uri, contacts,
   * default_acr_values, default_max_age, grant_types, id_token_signed_response_alg,
   * initiate_login_uri, jwks, jwks_uri, logo_uri, policy_uri, post_logout_redirect_uris,
   * redirect_uris, require_auth_time, response_types, scope, sector_identifier_uri, subject_type,
   * token_endpoint_auth_method, tos_uri, userinfo_signed_response_alg
   *
   * <br/><br/>The following metadata is available but may not be recognized depending on your
   * provider's configuration.<br/><br/>
   *
   * authorization_encrypted_response_alg, authorization_encrypted_response_enc,
   * authorization_signed_response_alg, backchannel_logout_session_required, backchannel_logout_uri,
   * frontchannel_logout_session_required, frontchannel_logout_uri, id_token_encrypted_response_alg,
   * id_token_encrypted_response_enc, introspection_encrypted_response_alg,
   * introspection_encrypted_response_enc, introspection_endpoint_auth_method,
   * introspection_endpoint_auth_signing_alg, introspection_signed_response_alg,
   * request_object_encryption_alg, request_object_encryption_enc, request_object_signing_alg,
   * request_uris, revocation_endpoint_auth_method, revocation_endpoint_auth_signing_alg,
   * tls_client_auth_san_dns, tls_client_auth_san_email, tls_client_auth_san_ip,
   * tls_client_auth_san_uri, tls_client_auth_subject_dn,
   * tls_client_certificate_bound_access_tokens, token_endpoint_auth_signing_alg,
   * userinfo_encrypted_response_alg, userinfo_encrypted_response_enc, web_message_uris
   *
   */
  clients: [],

  /*
   * clientDefaults
   *
   * description: Default client metadata to be assigned when unspecified by the client metadata,
   * e.g. during Dynamic Client Registration or for statically configured clients. The default value
   * does not represent all default values, but merely copies its subset. You can provide any used
   * client metadata property in this object.
   *
   * example: Changing the default client token_endpoint_auth_method
   *
   * To change the default client token_endpoint_auth_method configure `clientDefaults` to be an
   * object like so:
   *
   * ```js
   * {
   *   token_endpoint_auth_method: 'client_secret_post'
   * }
   * ```
   * example: Changing the default client response type to `code id_token`
   *
   * To change the default client response_types configure `clientDefaults` to be an
   * object like so:
   *
   * ```js
   * {
   *   response_types: ['code id_token'],
   *   grant_types: ['authorization_code', 'implicit'],
   * }
   * ```
   *
   */
  clientDefaults: {
    grant_types: ['authorization_code'],
    id_token_signed_response_alg: 'RS256',
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
  },


  /*
   * clockTolerance
   *
   * description: A `Number` value (in seconds) describing the allowed system clock skew for
   *   validating client-provided JWTs, e.g. Request Objects, DPoP Proofs and otherwise comparing
   *   timestamps
   * recommendation: Only set this to a reasonable value when needed to cover server-side client and
   *   oidc-provider server clock skew. More than 5 minutes (if needed) is probably a sign something
   *   else is wrong.
   */
  clockTolerance: 0,


  /*
   * conformIdTokenClaims
   *
   * title: ID Token only contains End-User claims when the requested `response_type` is `id_token`
   *
   * description: [Core 1.0 - Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
   * defines that claims requested using the `scope` parameter are only returned from the UserInfo
   * Endpoint unless the `response_type` is `id_token`. This is the default oidc-provider behaviour,
   * you can turn this behaviour off and return End-User claims with all ID Tokens by providing
   * this configuration as `false`.
   *
   */
  conformIdTokenClaims: true,


  /*
   * cookies
   *
   * description: Options for the [cookie module](https://github.com/pillarjs/cookies#cookiesset-name--value---options--)
   *   used to keep track of various User-Agent states.
   * @nodefault
   */
  cookies: {
    /*
     * cookies.names
     *
     * description: Cookie names used to store and transfer various states.
     */
    names: {
      session: '_session', // used for main session reference
      interaction: '_interaction', // used by the interactions for interaction session reference
      resume: '_interaction_resume', // used when interactions resume authorization for interaction session reference
      state: '_state', // prefix for sessionManagement state cookies => _state.{clientId}
    },

    /*
     * cookies.long
     *
     * description: Options for long-term cookies
     * recommendation: set cookies.keys and cookies.long.signed = true
     */
    long: {
      httpOnly: true, // cookies are not readable by client-side javascript
      maxAge: (14 * 24 * 60 * 60) * 1000, // 14 days in ms
      overwrite: true,
      sameSite: 'none',
    },

    /*
     * cookies.short
     *
     * description: Options for short-term cookies
     * recommendation: set cookies.keys and cookies.short.signed = true
     */
    short: {
      httpOnly: true, // cookies are not readable by client-side javascript
      maxAge: (10 * 60) * 1000, // 10 minutes in ms
      overwrite: true,
      sameSite: 'lax',
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
   */
  extraParams: [],


  /*
   * features
   * description: Enable/disable features. Some features are still either based on draft or
   *   experimental RFCs. Enabling those will produce a warning in your console and you must
   *   be aware that breaking changes may occur between draft implementations and that those
   *   will be published as minor versions of oidc-provider. See the example below on how to
   *   acknowledge the specification is a draft (this will remove the warning log) and ensure
   *   the provider instance will fail to instantiate if a new version of oidc-provider bundles
   *   newer version of the RFC with breaking changes in it.
   *
   * example: Acknowledging a draft / experimental feature
   *
   * ```js
   * new Provider('http://localhost:3000', {
   *   features: {
   *     webMessageResponseMode: {
   *       enabled: true,
   *     },
   *   },
   * });
   *
   * // The above code produces this NOTICE
   * // NOTICE: The following draft features are enabled and their implemented version not acknowledged
   * // NOTICE:   - OAuth 2.0 Web Message Response Mode - draft 00 (This is an Individual draft. URL: https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00)
   * // NOTICE: Breaking changes between draft version updates may occur and these will be published as MINOR semver oidc-provider updates.
   * // NOTICE: You may disable this notice and these potentially breaking updates by acknowledging the current draft version. See https://github.com/panva/node-oidc-provider/tree/v6.6.2/docs/README.md#features
   *
   * new Provider('http://localhost:3000', {
   *   features: {
   *     webMessageResponseMode: {
   *       enabled: true,
   *       ack: 0, // < we're acknowledging draft 00 of the RFC
   *     },
   *   },
   * });
   * // No more NOTICE, at this point if the draft implementation changed to 01 and contained no breaking
   * // changes, you're good to go, still no NOTICE, your code is safe to run.
   *
   * // Now lets assume you upgrade oidc-provider version and it bundles draft 02 and it contains breaking
   * // changes
   * new Provider('http://localhost:3000', {
   *   features: {
   *     webMessageResponseMode: {
   *       enabled: true,
   *       ack: 0, // < bundled is 2, but we're still acknowledging 0
   *     },
   *   },
   * });
   * // Thrown:
   * // Error: An unacknowledged version of a draft feature is included in this oidc-provider version.
   * ```
   * @nodefault
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
    devInteractions: { enabled: true },

    /*
     * features.dPoP
     *
     * title: [draft-fett-oauth-dpop-02](https://tools.ietf.org/html/draft-fett-oauth-dpop-02) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer
     *
     * description: Enables `DPoP` - mechanism for sender-constraining tokens via a
     * proof-of-possession mechanism on the application level
     */
    dPoP: { enabled: false, iatTolerance: 60 },

    /*
     * features.backchannelLogout
     *
     * title: [Back-Channel Logout 1.0 - draft 04](https://openid.net/specs/openid-connect-backchannel-1_0-04.html)
     *
     * description: Enables Back-Channel Logout features.
     *
     */
    backchannelLogout: { enabled: false },

    /*
     * features.ietfJWTAccessTokenProfile
     *
     * title: [draft-ietf-oauth-access-token-jwt-02](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-02) - JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
     *
     * description: Enables the use of `jwt-ietf` JWT Access Token format
     *
     */
    ietfJWTAccessTokenProfile: { enabled: false },


    /*
     * features.mTLS
     *
     * title: [draft-ietf-oauth-mtls-17](https://tools.ietf.org/html/draft-ietf-oauth-mtls-17) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens
     *
     * description: Enables specific features from the Mutual TLS specification. The three main
     * features have their own specific setting in this feature's configuration object and
     * you must provide functions for resolving some of the functions which are deployment-specific.
     * Note: **This feature is only supported in node runtime >= 12.0.0**
     *
     */
    mTLS: {
      enabled: false,

      /*
       * features.mTLS.certificateBoundAccessTokens
       *
       * description: Enables section 3 & 4 Mutual TLS Client Certificate-Bound Tokens
       */
      certificateBoundAccessTokens: false,

      /*
       * features.mTLS.selfSignedTlsClientAuth
       *
       * description: Enables section 2.2. Self-Signed Certificate Mutual TLS client authentication Method
       */
      selfSignedTlsClientAuth: false,

      /*
       * features.mTLS.tlsClientAuth
       *
       * description: Enables section 2.1. PKI Mutual TLS client authentication method
       */
      tlsClientAuth: false,

      /*
       * features.mTLS.getCertificate
       *
       * description: Function used to retrieve the PEM-formatted client certificate used
       *   in the request.
       *
       * example: When behind a TLS terminating proxy (nginx/apache)
       *
       * When behind a TLS terminating proxy it is common that the certificate be passed
       * to the application as a sanitized header. This returns the chosen header value provided
       * by nginx's `$ssl_client_cert` or apache's `%{SSL_CLIENT_CERT}s`
       *
       * ```js
       * function getCertificate(ctx) {
       *   return ctx.get('x-ssl-client-cert');
       * }
       * ```
       *
       * example: When using node's `https.createServer`
       *
       * ```js
       * function getCertificate(ctx) {
       *   const peerCertificate = ctx.socket.getPeerCertificate();
       *   if (peerCertificate.raw) {
       *     return `-----BEGIN CERTIFICATE-----\n${peerCertificate.raw.toString('base64')}\n-----END CERTIFICATE-----`;
       *   }
       * }
       * ```
       *
       * @nodefault
       */
      /* istanbul ignore next */
      getCertificate(ctx) { // eslint-disable-line no-unused-vars
        mustChange('features.mTLS.getCertificate', 'retrieve the PEM-formatted client certificate from the request context');
        throw new Error('features.mTLS.getCertificate function not configured');
      },

      /*
       * features.mTLS.certificateAuthorized
       *
       * description: Function used to determine if the client certificate, used in the
       *   request, is verified and comes from a trusted CA for the client. Should return true/false.
       *   Only used for `tls_client_auth` client authentication method.
       *
       * example: When behind a TLS terminating proxy (nginx/apache)
       *
       * When behind a TLS terminating proxy it is common that this detail be passed
       * to the application as a sanitized header. This returns the chosen header value provided
       * by nginx's `$ssl_client_verify` or apache's `%{SSL_CLIENT_VERIFY}s`
       *
       * ```js
       * function certificateAuthorized(ctx) {
       *   return ctx.get('x-ssl-client-verify') === 'SUCCESS';
       * }
       * ```
       *
       * example: When using node's `https.createServer`
       *
       * ```js
       * function certificateAuthorized(ctx) {
       *   return ctx.socket.authorized;
       * }
       * ```
       *
       * @nodefault
       */
      /* istanbul ignore next */
      certificateAuthorized(ctx) { // eslint-disable-line no-unused-vars
        mustChange('features.mTLS.getCertificate', 'determine if the client certificate is verified and comes from a trusted CA');
        throw new Error('features.mTLS.certificateAuthorized function not configured');
      },

      /*
       * features.mTLS.certificateSubjectMatches
       *
       * description: Function used to determine if the client certificate, used in the
       *   request, subject matches the registered client property. Only used for `tls_client_auth`
       *   client authentication method.
       *
       * example: When behind a TLS terminating proxy (nginx/apache)
       *
       * TLS terminating proxies can pass a header with the Subject DN pretty easily, for Nginx
       * this would be `$ssl_client_s_dn`, for apache `%{SSL_CLIENT_S_DN}s`.
       *
       * ```js
       * function certificateSubjectMatches(ctx, property, expected) {
       *   switch (property) {
       *     case 'tls_client_auth_subject_dn':
       *       return ctx.get('x-ssl-client-s-dn') === expected;
       *     default:
       *       throw new Error(`${property} certificate subject matching not implemented`);
       *   }
       * }
       * ```
       *
       * @nodefault
       */
      /* istanbul ignore next */
      certificateSubjectMatches(ctx, property, expected) { // eslint-disable-line no-unused-vars
        mustChange('features.mTLS.getCertificate', 'verify that the tls_client_auth_* registered client property value matches the certificate one');
        throw new Error('features.mTLS.certificateSubjectMatches function not configured');
      },
    },

    /*
     * features.claimsParameter
     *
     * title: [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) - Requesting Claims using the "claims" Request Parameter
     *
     * description: Enables the use and validations of `claims` parameter as described in the
     * specification.
     *
     */
    claimsParameter: { enabled: false },

    /*
     * features.clientCredentials
     *
     * title: [RFC6749](https://tools.ietf.org/html/rfc6749#section-1.3.4) - Client Credentials
     *
     * description: Enables `grant_type=client_credentials` to be used on the token endpoint.
     */
    clientCredentials: { enabled: false },

    /*
     * features.deviceFlow
     *
     * title: [RFC8628](https://tools.ietf.org/html/rfc8628) - OAuth 2.0 Device Authorization Grant
     *
     * description: Enables Device Authorization Grant (Device Flow)
     */
    deviceFlow: {
      enabled: false,

      /*
       * features.deviceFlow.charset
       *
       * description: alias for a character set of the generated user codes. Supported values are
       *   - `base-20` uses BCDFGHJKLMNPQRSTVWXZ
       *   - `digits` uses 0123456789
       */
      charset: 'base-20',

      /*
       * features.deviceFlow.mask
       *
       * description: a string used as a template for the generated user codes, `*` characters will
       *   be replaced by random chars from the charset, `-`(dash) and ` ` (space) characters may be
       *   included for readability. See the RFC for details about minimal recommended entropy
       */
      mask: '****-****',

      /*
       * features.deviceFlow.deviceInfo
       *
       * description: Function used to extract details from the device authorization endpoint
       *   request. This is then available during the end-user confirm screen and is supposed to
       *   aid the user confirm that the particular authorization initiated by the user from a
       *   device in his possession
       */
      deviceInfo(ctx) {
        return {
          ip: ctx.ip,
          ua: ctx.get('user-agent'),
        };
      },
      /*
       * features.deviceFlow.userCodeInputSource
       *
       * description: HTML source rendered when device code feature renders an input prompt for the
       *   User-Agent.
       */
      async userCodeInputSource(ctx, form, out, err) {
        // @param ctx - koa request context
        // @param form - form source (id="op.deviceInputForm") to be embedded in the page and submitted
        //   by the End-User.
        // @param out - if an error is returned the out object contains details that are fit to be
        //   rendered, i.e. does not include internal error messages
        // @param err - error object with an optional userCode property passed when the form is being
        //   re-rendered due to code missing/invalid/expired
        shouldChange('features.deviceFlow.userCodeInputSource', 'customize the look of the user code input page');
        let msg;
        if (err && (err.userCode || err.name === 'NoCodeError')) {
          msg = '<p class="red">The code you entered is incorrect. Try again</p>';
        } else if (err && err.name === 'AbortedError') {
          msg = '<p class="red">The Sign-in request was interrupted</p>';
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
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}p.red{color:#d50000}input[type=email],input[type=password],input[type=text]{height:44px;font-size:16px;width:100%;margin-bottom:10px;-webkit-appearance:none;background:#fff;border:1px solid #d9d9d9;border-top:1px solid silver;padding:0 8px;box-sizing:border-box;-moz-box-sizing:border-box}[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative;text-align:center;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}[type=submit]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}input[type=text]{text-transform:uppercase;text-align: center}input[type=text]::placeholder{text-transform: none}
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
       * features.deviceFlow.userCodeConfirmSource
       *
       * description: HTML source rendered when device code feature renders an a confirmation prompt for
       *   ther User-Agent.
       */
      async userCodeConfirmSource(ctx, form, client, deviceInfo, userCode) { // eslint-disable-line no-unused-vars
        // @param ctx - koa request context
        // @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
        //   submitted by the End-User.
        // @param deviceInfo - device information from the device_authorization_endpoint call
        // @param userCode - formatted user code by the configured mask
        shouldChange('features.deviceFlow.userCodeConfirmSource', 'customize the look of the user code confirmation page');
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
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);.help,h1,h1+p{text-align:center}h1,h1+p{font-weight:100}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#f7f7f7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}button[autofocus]{width:100%;display:block;margin-bottom:10px;position:relative;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button[autofocus]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}button[name=abort]{background:0 0!important;border:none;padding:0!important;font:inherit;cursor:pointer}a,button[name=abort]{text-decoration:none;color:#666;font-weight:400;display:inline-block;opacity:.6}.help{width:100%;font-size:12px}code{font-size:2em}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Confirm Device</h1>
        <p>
          <strong>${clientName || clientId}</strong>
          <br/><br/>
          The following code should be displayed on your device<br/><br/>
          <code>${userCode}</code>
          <br/><br/>
          <small>If you did not initiate this action, the code does not match or are unaware of such device in your possession please close this window or click abort.</small>
        </p>
        ${form}
        <button autofocus type="submit" form="op.deviceConfirmForm">Continue</button>
        <div class="help">
          <button type="submit" form="op.deviceConfirmForm" value="yes" name="abort">[ Abort ]</button>
        </div>
      </div>
    </body>
    </html>`;
      },


      /*
       * features.deviceFlow.successSource
       *
       * description: HTML source rendered when device code feature renders a success page for the
       *   User-Agent.
       */
      async successSource(ctx) {
        // @param ctx - koa request context
        shouldChange('features.deviceFlow.successSource', 'customize the look of the device code success page');
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
        <p>Your sign-in ${clientName ? `with ${clientName}` : ''} was successful, you can now close this page.</p>
      </div>
    </body>
    </html>`;
      },
    },

    /*
     * features.encryption
     *
     * description: Enables encryption features such as receiving encrypted UserInfo responses,
     * encrypted ID Tokens and allow receiving encrypted Request Objects.
     */
    encryption: { enabled: false },

    /*
     * features.fapiRW
     *
     * title: [Financial-grade API - Part 2: Read and Write API Security Profile](https://openid.net/specs/openid-financial-api-part-2-ID2.html)
     *
     * description: Enables extra behaviours defined in FAPI Part 1 & 2 that cannot be achieved by
     * other configuration options, namely:
     *
     * - Request Object `exp` claim is REQUIRED
     * - `userinfo_endpoint` becomes a FAPI resource, echoing back the x-fapi-interaction-id header
     *   and disabling query string as a mechanism for providing access tokens
     *
     * example: other configuration needed to reach FAPI levels
     *
     * - `clientDefaults` for setting different default client `token_endpoint_auth_method`
     * - `clientDefaults` for setting different default client `id_token_signed_response_alg`
     * - `clientDefaults` for setting different default client `response_types`
     * - `clientDefaults` for setting client `tls_client_certificate_bound_access_tokens` to true
     * - `features.mTLS` and enable `certificateBoundAccessTokens`
     * - `features.mTLS` and enable `selfSignedTlsClientAuth` and/or `tlsClientAuth`
     * - `features.claimsParameter`
     * - `features.requestObjects` and enable `request` and/or `request_uri`
     * - `features.requestObjects.mergingStrategy.name` set to `strict`
     * - `whitelistedJWA`
     * - (optional) `features.pushedRequestObjects`
     * - (optional) `features.jwtResponseModes`
     */
    fapiRW: { enabled: false },

    /*
     * features.frontchannelLogout
     *
     * title: [Front-Channel Logout 1.0 - draft 02](https://openid.net/specs/openid-connect-frontchannel-1_0-02.html)
     *
     * description: Enables Front-Channel Logout features
     */
    frontchannelLogout: {
      enabled: false,

      /*
       * features.frontchannelLogout.logoutPendingSource
       *
       * description: HTML source rendered when there are pending front-channel logout iframes to be
       *   called to trigger RP logouts. It should handle waiting for the frames to be loaded as well
       *   as have a timeout mechanism in it.
       */
      async logoutPendingSource(ctx, frames, postLogoutRedirectUri) {
        shouldChange('features.frontchannelLogout.logoutPendingSource', 'customize the front-channel logout pending page');
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
          if (loaded === ${frames.length}) {
            redirect();
          }
        }
        Array.prototype.slice.call(document.querySelectorAll('iframe')).forEach(function (element) {
          element.onload = frameOnLoad;
        });
        setTimeout(redirect, 2500);
      </script>
      <noscript>
        Your browser does not support JavaScript or you've disabled it.<br/>
        <a href="${postLogoutRedirectUri}">Continue</a>
      </noscript>
    </body>
    </html>`;
      },
    },

    /*
     * features.introspection
     *
     * title: [RFC7662](https://tools.ietf.org/html/rfc7662) - OAuth 2.0 Token Introspection
     *
     * description: Enables Token Introspection features
     *
     */
    introspection: { enabled: false },

    /*
     * features.jwtIntrospection
     *
     * title: [draft-ietf-oauth-jwt-introspection-response-06](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-06) - JWT Response for OAuth Token Introspection
     *
     * description: Enables JWT responses for Token Introspection features
     *
     */
    jwtIntrospection: { enabled: false },


    /*
     * features.jwtResponseModes
     *
     * title: [openid-financial-api-jarm-wd-02](https://openid.net/specs/openid-financial-api-jarm-wd-02.html) - JWT Secured Authorization Response Mode (JARM)
     *
     * description: Enables JWT Secured Authorization Responses
     *
     */
    jwtResponseModes: { enabled: false },

    /*
     * features.pushedRequestObjects
     *
     * title: [openid-financial-api-pushed-request-object-37426f5](https://bitbucket.org/openid/fapi/src/37426f5/Financial_API_Pushed_Request_Object.md) - Pushed Request Object
     *
     * description: Enables the use `request_object_endpoint` defined by the Pushed Request Object
     * draft.
     *
     */
    pushedRequestObjects: { enabled: false },

    /*
     * features.registration
     *
     * title: [Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
     *
     * description: Enables Dynamic Client Registration.
     */
    registration: {
      enabled: false,

      /*
       * features.registration.initialAccessToken
       *
       * description: Enables registration_endpoint to check a valid initial access token is
       *   provided as a bearer token during the registration call. Supported types are
       *   - `string` the string value will be checked as a static initial access token
       *   - `boolean` true/false to enable/disable adapter backed initial access tokens
       *
       * example: To add an adapter backed initial access token and retrive its value
       *
       * ```js
       * new (provider.InitialAccessToken)({}).save().then(console.log);
       * ```
       */
      initialAccessToken: false,

      /*
       * features.registration.policies
       *
       * description: define registration and registration management policies applied to client
       *   properties. Policies are sync/async functions that are assigned to an Initial Access
       *   Token that run before the regular client property validations are run. Multiple policies
       *   may be assigned to an Initial Access Token and by default the same policies will transfer
       *   over to the Registration Access Token. A policy may throw / reject and it may modify the
       *   properties object.
       *
       * example: To define registration and registration management policies
       *
       * To define policy functions configure `features.registration` to be an object like so:
       * ```js
       * {
       *   enabled: true,
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
       * will be thrown inside the request context if it is not, resulting in a 500 Server Error.
       *
       * Note: the same policies will be assigned to the Registration Access Token after a successful
       * validation. If you wish to assign different policies to the Registration Access Token
       * ```js
       * // inside your final ran policy
       * ctx.oidc.entities.RegistrationAccessToken.policies = ['update-policy'];
       * ```
       *
       * example: Using Initial Access Token policies for software_statement dynamic client registration property
       *
       * Support modules:
       * ```js
       * const { verify } = require('jsonwebtoken');
       * const {
       *   errors: { InvalidSoftwareStatement, UnapprovedSoftwareStatement, InvalidClientMetadata },
       * } = require('oidc-provider');
       * ```
       *
       * features.registration configuration:
       * ```js
       * {
       *  enabled: true,
       *  initialAccessToken: true, // to enable adapter-backed initial access tokens
       *  policies: {
       *    'softwareStatement': async function (ctx, metadata) {
       *      if (!('software_statement' in metadata)) {
       *        throw new InvalidClientMetadata('software_statement must be provided');
       *      }
       *
       *      const softwareStatementKey = await loadKeyForThisPolicy();
       *
       *      const statement = metadata.software_statement;
       *
       *      let payload;
       *      try {
       *        payload = verify(value, softwareStatementKey, {
       *          algorithms: ['RS256'],
       *          issuer: 'Software Statement Issuer',
       *        });
       *
       *        if (!approvedStatement(value, payload)) {
       *          throw new UnapprovedSoftwareStatement('software_statement not approved for use');
       *        }
       *
       *        // cherry pick the software_statement values and assign them
       *        // Note: regular validations will run!
       *        const { client_name, client_uri } = payload;
       *        Object.assign(metadata, { client_name, client_uri });
       *      } catch (err) {
       *        throw new InvalidSoftwareStatement('could not verify software_statement');
       *      }
       *    },
       *  },
       * }
       * ```
       *
       * An Initial Access Token that requires and validates the given software statement is created like so
       * ```js
       * new (provider.InitialAccessToken)({ policies: ['softwareStatement'] }).save().then(console.log);
       * ```
       */
      policies: undefined,

      /*
       * features.registration.idFactory
       *
       * description: Function used to generate random client identifiers during dynamic
       *   client registration
       */
      idFactory() {
        return nanoid();
      },

      /*
       * features.registration.secretFactory
       *
       * description: Function used to generate random client secrets during dynamic
       *   client registration
       */
      secretFactory() {
        return base64url.encodeBuffer(crypto.randomBytes(64)); // 512 base64url random bits
      },
    },

    /*
     * features.registrationManagement
     *
     * title: [OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)
     *
     * description: Enables Update and Delete features described in the RFC
     */
    registrationManagement: {
      enabled: false,

      /*
       * features.registrationManagement.rotateRegistrationAccessToken
       *
       * description: Enables registration access token rotation. The provider will discard the
       *   current Registration Access Token with a successful update and issue a new one, returning
       *   it to the client with the Registration Update Response. Supported
       *   values are
       *   - `false` registration access tokens are not rotated
       *   - `true` registration access tokens are rotated when used
       *   - function returning true/false, true when rotation should occur, false when it shouldn't
       * example: function use
       * ```js
       * {
       *   features: {
       *     registrationManagement: {
       *       enabled: true,
       *       async rotateRegistrationAccessToken(ctx) {
       *         // return tokenRecentlyRotated(ctx.oidc.entities.RegistrationAccessToken);
       *         // or
       *         // return customClientBasedPolicy(ctx.oidc.entities.Client);
       *       }
       *     }
       *   }
       * }
       * ```
       */
      rotateRegistrationAccessToken: false,
    },

    /*
     * features.resourceIndicators
     *
     * title: [draft-ietf-oauth-resource-indicators-07](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-07) - Resource Indicators for OAuth 2.0
     *
     * description: Enables the use of `resource` parameter for the authorization and token
     *   endpoints. In order for the feature to be any useful you must also use the `audiences`
     *   function to validate the resource(s) and transform it to the Access Token audience.
     *
     * example: Example use
     * This example
     * - will transform resources to audience and push them down to the audience of access tokens
     * - will take both, the parameter and previously granted resources into consideration
     * - assumes resource parameters are validated using `features.resourceIndicators.allowedPolicy`
     *
     * ```js
     * // const { InvalidTarget } = Provider.errors;
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
     *       // => array of validated and transformed string audiences or undefined if no audiences
     *       //    are to be listed
     *       return transform(resourceParam, grantedResource);
     *     }
     *   },
     *   formats: {
     *     AccessToken(ctx, token) {
     *       return token.aud ? 'jwt' : 'opaque';
     *     }
     *   },
     *   // ...
     * }
     * ```
     */
    resourceIndicators: {
      enabled: false,

      /*
       * features.resourceIndicators.allowedPolicy
       *
       * description: Function used to check if a request parameter should be
       *   processed, e.g. if it is whitelisted for a given client.
       *
       * recommendation: Only allow pre-registered resource values, to pre-register these you
       *   shall use the `extraClientMetadata` configuration option to define a custom metadata
       *   and use that to implement your policy using this function.
       */
      async allowedPolicy(ctx, resources, client) { // eslint-disable-line no-unused-vars
        shouldChange('features.resourceIndicators.allowedPolicy', 'to whitelist resource values based on the client and request context');

        return true;
      },
    },

    /*
     * features.requestObjects
     *
     * title: [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject) and [JWT Secured Authorization Request (JAR)](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-19) - Request Object
     *
     * description: Enables the use and validations of the `request` and/or `request_uri`
     *   parameters.
     */
    requestObjects: {

      /*
       * features.requestObjects.request
       *
       * description: Enables the use and validations of the `request` parameter.
       */
      request: false,

      /*
       * features.requestObjects.requestUri
       *
       * description: Enables the use and validations of the `request_uri` parameter.
       */
      requestUri: true,

      /*
       * features.requestObjects.requireUriRegistration
       *
       * description: Makes request_uri pre-registration mandatory (true) or optional (false).
       */
      requireUriRegistration: true,

      mergingStrategy: {

        /*
         * features.requestObjects.mergingStrategy.name
         *
         * description: defines the provider's strategy when it comes to using regular OAuth 2.0
         * parameters that are present. Parameters inside the Request Object are ALWAYS used,
         * this option controls whether to combine those with the regular ones or not.
         *
         * Supported values are:
         *
         * - 'lax' (default) This is the behaviour expected by OIDC Core 1.0 - all parameters that
         *   are not present in the Resource Object are used when resolving the authorization
         *   request.
         * - 'strict' This is the behaviour expected by FAPI or JAR, all parameters outside of the
         *   Request Object are ignored.
         * - 'whitelist' During this strategy only parameters in the configured whitelist are used.
         *   This means that pre-signed Request Objects could be used multiple times while the
         *   per-transaction whitelisted parameters can be provided using regular OAuth 2.0 syntax.
         *
         */
        name: 'lax',

        /*
         * features.requestObjects.mergingStrategy.whitelist
         *
         * description: This whitelist is only used when the 'mergingStrategy.name' value is
         * 'whitelist'.
         *
         */
        whitelist: ['code_challenge', 'nonce', 'state'], // TODO: in v7.x add `prompt` here
      },
    },

    /*
     * features.revocation
     *
     * title: [RFC7009](https://tools.ietf.org/html/rfc7009) - OAuth 2.0 Token Revocation
     *
     * description: Enables Token Revocation
     *
     */
    revocation: { enabled: false },

    /*
     * features.sessionManagement
     *
     * title: [Session Management 1.0 - draft 28](https://openid.net/specs/openid-connect-session-1_0-28.html)
     *
     * description: Enables Session Management features.
     */
    sessionManagement: {
      enabled: false,

      /*
       * features.sessionManagement.keepHeaders
       *
       * description: Enables/Disables removing frame-ancestors from Content-Security-Policy and
       * X-Frame-Options headers.
       * recommendation: Only enable this if you know what you're doing either in a followup
       * middleware or your app server, otherwise you shouldn't have the need to touch this option.
       */
      keepHeaders: false,
    },

    /*
     * features.userinfo
     *
     * title: [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - UserInfo Endpoint
     *
     * description: Enables the userinfo endpoint.
     */
    userinfo: {
      enabled: true,
    },


    /*
     * features.jwtUserinfo
     *
     * title: [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - JWT UserInfo Endpoint Responses
     *
     * description: Enables the userinfo to optionally return signed and/or encrypted JWTs, also
     * enables the relevant client metadata for setting up signing and/or encryption
     */
    jwtUserinfo: {
      enabled: true,
    },

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
    webMessageResponseMode: { enabled: false },
  },

  /*
   * extraAccessTokenClaims
   *
   * description: Function used to get additional access token claims
   *   when it is being issued. These claims will be available in your storage under
   *   property `extra`, returned by introspection as top level claims and pushed into `jwt`,
   *   `jwt-ietf` and `paseto` formatted tokens as top level claims as well. Returned claims may not
   *   overwrite other top level claims.
   *
   * example: To push additional claims to an Access Token
   * ```js
   * {
   *   extraAccessTokenClaims(ctx, token) {
   *     return {
   *       'urn:oidc-provider:example:foo': 'bar',
   *     };
   *   }
   * }
   * ```
   */
  async extraAccessTokenClaims(ctx, token) { // eslint-disable-line no-unused-vars
    return undefined;
  },

  /*
   * formats
   *
   * description: This option allows to configure the token serialization format. The different
   *   values change how a client-facing token value is generated as well as what properties get
   *   sent to the adapter for storage.
   *   - `opaque` (default) formatted tokens store every property as a root property in your adapter
   *   - `jwt` formatted tokens are issued as JWTs and stored the same as `opaque` only with
   *     additional property `jwt`. See `formats.jwtAccessTokenSigningAlg` for resolving the JWT
   *     Access Token signing algorithm.
   *     Note this is a proprietary format that will eventually get deprecated in favour of the
   *     'jwt-ietf' value (once it gets stable and close to being an RFC)
   *   - `jwt-ietf` formatted tokens are issued as JWTs and stored the same as `opaque` only with
   *     additional property `jwt-ietf`. See `formats.jwtAccessTokenSigningAlg` for resolving the
   *     JWT Access Token signing algorithm.
   *     This is an implementation of
   *     [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-02)
   *     draft and to enable it you need to enable `features.ietfJWTAccessTokenProfile`.
   *     'jwt-ietf' value (once it gets stable and close to being an RFC)
   *   - `paseto` formatted tokens are issued as v2.public PASETOs and stored the same as `opaque`
   *     only with additional property `paseto`. The server must have an `OKP Ed25519` key available
   *     to sign with else it will throw a server error. PASETOs are also allowed to only have a
   *     single audience, if the token's "aud" resolves with more than one the server will throw a
   *     server error. **This format is only supported in node runtime >= 12.0.0**
   *   - the value may also be a function dynamically determining the format (returning either
   *     `jwt`, `jwt-ietf`, `paseto` or `opaque` depending on the token itself)
   *
   * example: To enable JWT Access Tokens
   *
   * Configure `formats`:
   * ```js
   * { AccessToken: 'jwt' }
   * ```
   *
   * example: To enable PASETO v2.public Access Tokens
   *
   * Configure `formats`:
   * ```js
   * { AccessToken: 'paseto' }
   * ```
   *
   * example: To dynamically decide on the format used, e.g. only if it is intended for a resource
   *   server
   *
   * Configure `formats`:
   * ```js
   * {
   *   AccessToken(ctx, token) {
   *     return token.aud ? 'jwt' : 'opaque';
   *   }
   * }
   * ```
   */
  formats: {
    /*
     * formats.jwtAccessTokenSigningAlg
     *
     * description: Function used to resolve a JWT Access Token signing algorithm.
     *   The resolved algorithm must be an asymmetric one supported by the provider's keys in jwks.
     */
    async jwtAccessTokenSigningAlg(ctx, token, client) { // eslint-disable-line no-unused-vars
      if (client && client.idTokenSignedResponseAlg !== 'none' && !client.idTokenSignedResponseAlg.startsWith('HS')) {
        return client.idTokenSignedResponseAlg;
      }

      return 'RS256';
    },
    AccessToken: 'opaque',
    ClientCredentials: 'opaque',

    /*
     * formats.customizers
     *
     * description: Functions used before signing a structured Access Token of a
     * given type, such as a JWT or PASETO one. Customizing here only changes the structured Access
     * Token, not your storage, introspection or anything else. For such extras use
     * [`extraAccessTokenClaims`](#extraaccesstokenclaims) instead.
     *
     * example: To push additional claims to a `jwt` format Access Token payload
     * ```js
     * {
     *   customizers: {
     *     jwt(ctx, token, jwt) {
     *       jwt.payload.foo = 'bar';
     *     }
     *   }
     * }
     * ```
     *
     * example: To push additional headers to a `jwt` format Access Token
     * ```js
     * {
     *   customizers: {
     *     jwt(ctx, token, jwt) {
     *       jwt.header = { foo: 'bar' };
     *     }
     *   }
     * }
     * ```
     *
     * example: To push additional claims to a `jwt-ietf` format Access Token payload
     * ```js
     * {
     *   customizers: {
     *     ['jwt-ietf'](ctx, token, jwt) {
     *       jwt.payload.foo = 'bar';
     *     }
     *   }
     * }
     * ```
     *
     * example: To push additional headers to a `jwt-ietf` format Access Token
     * ```js
     * {
     *   customizers: {
     *     ['jwt-ietf'](ctx, token, jwt) {
     *       jwt.header = { foo: 'bar' };
     *     }
     *   }
     * }
     * ```
     *
     * example: To push a payload and a footer to a PASETO structured access token
     * ```js
     * {
     *   customizers: {
     *     paseto(ctx, token, structuredToken) {
     *       structuredToken.payload.foo = 'bar';
     *       structuredToken.footer = 'foo'
     *       structuredToken.footer = Buffer.from('foo')
     *       structuredToken.footer = { foo: 'bar' } // will get stringified
     *     }
     *   }
     * }
     * ```
     */
    customizers: {
      jwt: undefined,
      'jwt-ietf': undefined,
      paseto: undefined,
    },
  },

  /*
   * httpOptions
   *
   * description: Function called whenever calls to an external HTTP(S) resource are being made.
   * Use this to change the [got](https://github.com/sindresorhus/got/tree/v9.6.0) library's request
   * options as these requests are being made. This can be used to e.g. change the request timeout
   * option or to configure the global agent to use HTTP_PROXY and HTTPS_PROXY environment
   * variables.
   *
   * example: To change the request's timeout
   *
   * To change all request's timeout configure the httpOptions as a function like so:
   *
   * ```js
   *  {
   *    httpOptions(options) {
   *      options.timeout = 5000;
   *      return options;
   *    }
   *  }
   * ```
   */
  /* istanbul ignore next */
  httpOptions(options) {
    /* eslint-disable no-param-reassign */
    options.followRedirect = false;
    options.headers['User-Agent'] = 'oidc-provider/${VERSION} (${ISSUER_IDENTIFIER})'; // eslint-disable-line no-template-curly-in-string
    options.retry = 0;
    options.throwHttpErrors = false;
    options.timeout = 2500;
    /* eslint-enable no-param-reassign */
    return options;
  },

  /*
   * expiresWithSession
   * description: Function used to decide whether the given authorization code/ device code
   *   or implicit returned access token be bound to the user session. This will be applied to all
   *   tokens issued from the authorization / device code in the future. When tokens are session-bound
   *   the session will be loaded by its `uid` every time the token is encountered. Session bound
   *   tokens will effectively get revoked if the end-user logs out.
   */
  async expiresWithSession(ctx, token) {
    return !token.scopes.has('offline_access');
  },


  /*
   * issueRefreshToken
   *
   * description: Function used to decide whether a refresh token will be issued or not
   *
   * example: To always issue a refresh tokens ...
   * ... if a client has the grant whitelisted and scope includes offline_access or the client is a
   * public web client doing code flow. Configure `issueRefreshToken` like so
   *
   * ```js
   * async issueRefreshToken(ctx, client, code) {
   *   if (!client.grantTypes.includes('refresh_token')) {
   *     return false;
   *   }
   *
   *   return code.scopes.has('offline_access') || (client.applicationType === 'web' && client.tokenEndpointAuthMethod === 'none');
   * }
   * ```
   */
  async issueRefreshToken(ctx, client, code) {
    return client.grantTypes.includes('refresh_token') && code.scopes.has('offline_access');
  },


  /*
   * jwks
   *
   * description: JSON Web Key Set used by the provider for signing and encryption. The object must
   * be in [JWK Set format](https://tools.ietf.org/html/rfc7517#section-5). All provided keys must
   * be private keys. **Note:** Be sure to follow best practices for distributing private keying material and secrets
   * for your respective target deployment environment.
   *
   *
   * Supported key types are:
   *
   * - RSA
   * - OKP (Ed25519 and Ed448 curves)
   * - EC (P-256, P-384 and P-521 curves)
   *
   * example: Generating keys
   *
   * ```js
   * const { JWKS: { KeyStore } } = require('@panva/jose');
   * const keystore = new KeyStore();
   * keystore.generateSync('RSA', 2048, {
   *   alg: 'RS256',
   *   use: 'sig',
   * });
   * console.log('this is the full private JWKS:\n', keystore.toJWKS(true));
   * ```
   *
   * example: Generating keys for both signing and encryption
   *
   * Re-using the same keys for both encryption and signing is discouraged so it is best to generate
   * one with `{ use: 'sig' }` and another with `{ use: 'enc' }`, e.g.
   *
   * ```js
   * const { JWKS: { KeyStore } } = require('@panva/jose');
   * const keystore = new KeyStore();
   * Promise.all([
   *   keystore.generate('RSA', 2048, {
   *     use: 'sig',
   *   }),
   *   keystore.generate('RSA', 2048, {
   *     use: 'enc',
   *   }),
   *   keystore.generate('EC', 'P-256', {
   *     use: 'sig',
   *   }),
   *   keystore.generate('EC', 'P-256', {
   *     use: 'enc',
   *   }),
   *   keystore.generate('OKP', 'Ed25519', {
   *     use: 'sig',
   *   }),
   * ]).then(function () {
   *   console.log('this is the full private JWKS:\n', keystore.toJWKS(true));
   * });
   * ```
   *
   * recommendation: **Provider key rotation** - The following action order is recommended when
   * rotating signing keys on a distributed deployment with rolling reloads in place.
   *
   * 1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become
   *    available for verification should they be encountered but not yet used for signing
   * 2. reload all your processes
   * 3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be
   *    used for signing after reload
   * 4. reload all your processes
   *
   * @nodefault
   *
   */
  jwks: DEV_KEYSTORE,


  /*
   * responseTypes
   *
   * description: Array of response_type values that OP supports. The default omits all response
   * types that result in access tokens being issued by the authorization endpoint directly as per
   * [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.1.2)
   * You can still enable them if you need to.
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
    'code id_token',
    'code',
    'id_token',
    'none',
  ],

  /*
   * pkceMethods
   *
   * description: fine-tune the supported code challenge methods. Supported values are
   *   - `S256`
   *   - `plain`
   */
  pkceMethods: ['S256'],


  /*
   * routes
   *
   * description: Routing values used by the OP. Only provide routes starting with "/"
   */
  routes: {
    authorization: '/auth',
    check_session: '/session/check',
    code_verification: '/device',
    device_authorization: '/device/auth',
    end_session: '/session/end',
    introspection: '/token/introspection',
    jwks: '/jwks',
    registration: '/reg',
    revocation: '/token/revocation',
    token: '/token',
    userinfo: '/me',
    request_object: '/request',
  },


  /*
   * scopes
   *
   * description: Array of the scope values that the OP supports
   */
  scopes: ['openid', 'offline_access'],


  /*
   * dynamicScopes
   *
   * description: Array of the dynamic scope values that the OP supports. These must be regular
   *   expressions that the OP will check string scope values, that aren't in the static list,
   *   against.
   *
   * example: To enable a dynamic scope values like `api:write:{hex id}` and `api:read:{hex id}`
   * Configure `dynamicScopes` like so:
   *
   * ```js
   * [
   *   /^api:write:[a-fA-F0-9]{2,}$/,
   *   /^api:read:[a-fA-F0-9]{2,}$/,
   * ]
   * ```
   */
  dynamicScopes: [],


  /*
   * subjectTypes
   *
   * description: Array of the Subject Identifier types that this OP supports. When only `pairwise`
   * is supported it becomes the default `subject_type` client metadata value. Valid types are
   *   - `public`
   *   - `pairwise`
   */
  subjectTypes: ['public'],


  /*
   * pairwiseIdentifier
   *
   * description: Function used by the OP when resolving pairwise ID Token and Userinfo sub claim
   *   values. See [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
   * recommendation: Since this might be called several times in one request with the same arguments
   *   consider using memoization or otherwise caching the result based on account and client
   *   ids.
   */
  async pairwiseIdentifier(ctx, accountId, client) {
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
   * example: Supported values list
   * ```js
   * [
   *   'none',
   *   'client_secret_basic', 'client_secret_post',
   *   'client_secret_jwt', 'private_key_jwt',
   *   'tls_client_auth', 'self_signed_tls_client_auth', // these methods are only available when features.mTLS is configured
   * ]
   * ```
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
   *
   * recommendation: Do not set token TTLs longer then they absolutely have to be, the shorter
   * the TTL, the better.
   *
   * recommendation: Rather than setting crazy high Refresh Token TTL look into `rotateRefreshToken`
   * configuration option which is set up in way that when refresh tokens are regularly used they
   * will have their TTL refreshed (via rotation). This is inline with the
   * [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13)
   *
   * example: To resolve a ttl on runtime for each new token
   * Configure `ttl` for a given token type with a function like so, this must return a value, not a
   * Promise.
   *
   * ```js
   * {
   *   ttl: {
   *     AccessToken(ctx, token, client) {
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
     *
     * example: Using extraClientMetadata to allow software_statement dynamic client registration property
     * ```js
     * const { verify } = require('jsonwebtoken');
     * const {
     *   errors: { InvalidSoftwareStatement, UnapprovedSoftwareStatement },
     * } = require('oidc-provider');
     * const softwareStatementKey = require('path/to/public/key');
     *
     * {
     *   extraClientMetadata: {
     *     properties: ['software_statement'],
     *     validator(key, value, metadata) {
     *       if (key === 'software_statement') {
     *         if (value === undefined) return;
     *
     *         // software_statement is not stored, but used to convey client metadata
     *         delete metadata.software_statement;
     *
     *         let payload;
     *         try {
     *           // extraClientMetadata.validator must be sync :sadface:
     *           payload = verify(value, softwareStatementKey, {
     *             algorithms: ['RS256'],
     *             issuer: 'Software Statement Issuer',
     *           });
     *
     *           if (!approvedStatement(value, payload)) {
     *             throw new UnapprovedSoftwareStatement('software_statement not approved for use');
     *           }
     *
     *           // cherry pick the software_statement values and assign them
     *           // Note: there will be no further validation ran on those values, so make sure
     *           //   they're conform
     *           const { client_name, client_uri } = payload;
     *           Object.assign(metadata, { client_name, client_uri });
     *         } catch (err) {
     *           throw new InvalidSoftwareStatement('could not verify software_statement');
     *         }
     *       }
     *     }
     *   }
     * }
     * ```
     */
    // TODO: in v7.x move ctx to be the first argument
    validator(key, value, metadata, ctx) { // eslint-disable-line no-unused-vars
      // @param key - the client metadata property name
      // @param value - the property value
      // @param metadata - the current accumulated client metadata
      // @param ctx - koa request context (only provided when a client is being constructed during
      //              Client Registration Request or Client Update Request

      // validations for key, value, other related metadata

      // throw new Provider.errors.InvalidClientMetadata() to reject the client metadata

      // metadata[key] = value; to (re)assign metadata values

      // return not necessary, metadata is already a reference
    },
  },

  /*
   * postLogoutSuccessSource
   *
   * description: HTML source rendered when session management feature concludes a logout but there
   *   was no `post_logout_redirect_uri` provided by the client.
   */
  async postLogoutSuccessSource(ctx) {
    // @param ctx - koa request context
    shouldChange('postLogoutSuccessSource', 'customize the look of the default post logout success page');
    const {
      clientId, clientName, clientUri, initiateLoginUri, logoUri, policyUri, tosUri, // eslint-disable-line no-unused-vars, max-len
    } = ctx.oidc.client || {}; // client is defined if the user chose to stay logged in with the OP
    const display = clientName || clientId;
    ctx.body = `<!DOCTYPE html>
<head>
  <meta charset="utf-8">
  <title>Sign-out Success</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <style>
    @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}
  </style>
</head>
<body>
  <div class="container">
    <h1>Sign-out Success</h1>
    <p>Your sign-out ${display ? `with ${display}` : ''} was successful.</p>
  </div>
</body>
</html>`;
  },


  /*
   * logoutSource
   *
   * description: HTML source rendered when session management feature renders a confirmation
   *   prompt for the User-Agent.
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
    ${form}
    <button autofocus type="submit" form="op.logoutForm" value="yes" name="logout">Yes, sign me out</button>
    <button type="submit" form="op.logoutForm">No, stay signed in</button>
  </div>
</body>
</html>`;
  },


  /*
   * renderError
   *
   * description: Function used to present errors to the User-Agent
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
    ${Object.entries(out).map(([key, value]) => `<pre><strong>${key}</strong>: ${htmlSafe(value)}</pre>`).join('')}
  </div>
</body>
</html>`;
  },


  /*
   * interactions
   *
   * description: Holds the configuration for interaction policy and url to send end-users to
   *   when the policy decides to require interaction.
   *
   * @nodefault
   */
  interactions: {
    /*
     * interactions.policy
     *
     * description: structure of Prompts and their checks formed by Prompt and Check class instances.
     *  The default you can get a fresh instance for and the classes are available under
     * `Provider.interactionPolicy`.
     *
     * example: default interaction policy description
     *
     * The default interaction policy consists of two available prompts, login and consent
     *
     * <br/><br/>
     *
     * - `login` does the following checks:
     *   - no_session - checks that there's an established session, a authenticated end-user
     *   - max_age - processes the max_age parameter (when the session's auth_time is too old it requires login)
     *   - id_token_hint - processes the id_token_hint parameter (when the end-user sub differs it requires login)
     *   - claims_id_token_sub_value - processes the claims parameter `sub` (when the `claims` parameter requested sub differs it requires login)
     *   - essential_acrs - processes the claims parameter `acr` (when the current acr is not amongst the `claims` parameter essential `acr.values` it requires login)
     *   - essential_acr - processes the claims parameter `acr` (when the current acr is not equal to the `claims` parameter essential `acr.value` it requires login)
     *
     * <br/><br/>
     *
     * - `consent` does the following checks:
     *   - client_not_authorized - every client needs to go through a consent once per end-user session
     *   - native_client_prompt - native clients always require re-consent
     *   - scopes_missing - when requested scope includes scope values previously not requested it requests consent
     *   - claims_missing - when requested claims parameter includes claims previously not requested it requests consent
     *
     * <br/><br/>
     *
     * These checks are the best practice for various privacy and security reasons.
     *
     * example: disabling default checks
     *
     * You may be required to skip (silently accept) some of the consent checks, while it is
     * discouraged there are valid reasons to do that, for instance in some first-party scenarios or
     * going with pre-existing, previously granted, consents.
     *
     * Definitely do not just remove the checks, remove and add ones that do the same operation with
     * the exception of those scenarios you want to skip and in those you'll have to call some of
     * the methods ran by the `returnTo` / `resume` flow by default to ensure smooth operation.
     *
     * - `ctx.oidc.session.ensureClientContainer(clientId<string>)` ensures the client namespace in the
     *   session is set up
     * - `ctx.oidc.session.promptedScopesFor(clientId<string>, scopes<Set|Array>)` - the scopes that
     *   were already prompted before hand
     * - `ctx.oidc.session.promptedClaimsFor(clientId<string>, claims<Set|Array>)`- the claims that
     *   were already prompted before hand
     * - `ctx.oidc.session.rejectedScopesFor(clientId<string>, scopes<Set|Array>)` - the scopes that
     *   were already prompted before hand but were rejected
     * - `ctx.oidc.session.rejectedClaimsFor(clientId<string>, claims<Set|Array>)` - the claims that
     *   were already prompted before hand but were rejected
     *
     * example: modifying the default interaction policy
     * ```js
     * const { interactionPolicy: { Prompt, Check, base } } = require('oidc-provider');
     *
     * const basePolicy = base()
     *
     * // basePolicy.get(name) => returns a Prompt instance by its name
     * // basePolicy.remove(name) => removes a Prompt instance by its name
     * // basePolicy.add(prompt, index) => adds a Prompt instance to a specific index, default is add the prompt as the last one
     *
     * // prompt.checks.get(reason) => returns a Check instance by its reason
     * // prompt.checks.remove(reason) => removes a Check instance by its reason
     * // prompt.checks.add(check, index) => adds a Check instance to a specific index, default is add the check as the last one
     * ```
     */
    policy: defaultPolicy(),

    /*
     * interactions.url
     *
     * description: Function used to determine where to redirect User-Agent for necessary
     *   interaction, can return both absolute and relative urls.
     */
    async url(ctx, interaction) { // eslint-disable-line no-unused-vars
      return `/interaction/${ctx.oidc.uid}`;
    },
  },


  /*
   * audiences
   *
   * description: Function used to set an audience to issued Access Tokens. The return value
   * should be either:
   *
   * - falsy (no audience, implicitly the client is the only allowed audience of the token)
   * - a single string `aud` value (e.g. such as the Resource Server indicated by the resource parameter)
   * - array of string `aud` values (it is supported but NOT RECOMMENDED, consider it DEPRECATED)
   *
   */
  async audiences(ctx, sub, token, use) { // eslint-disable-line no-unused-vars
    // @param ctx   - koa request context
    // @param sub   - account identifier (subject)
    // @param token - the token to which these additional audiences will be passed to
    // @param use   - can be one of "access_token" or "client_credentials"
    //   depending on where the specific audience is intended to be allowed
    return undefined;
  },


  /*
   * findAccount
   *
   * description: Function used to load an account and retrieve its available claims. The
   *   return value should be a Promise and #claims() can return a Promise too
   */
  async findAccount(ctx, sub, token) { // eslint-disable-line no-unused-vars
    // @param ctx - koa request context
    // @param sub {string} - account identifier (subject)
    // @param token - is a reference to the token used for which a given account is being loaded,
    //   is undefined in scenarios where claims are returned from authorization endpoint
    mustChange('findAccount', 'use your own account model');
    return {
      accountId: sub,
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
   * rotateRefreshToken
   *
   * description: Configures if and how the OP rotates refresh tokens after they are used. Supported
   *   values are
   *   - `false` refresh tokens are not rotated and their initial expiration date is final
   *   - `true` refresh tokens are rotated when used, current token is marked as
   *     consumed and new one is issued with new TTL, when a consumed refresh token is
   *     encountered an error is returned instead and the whole token chain (grant) is revoked
   *   - `function` returning true/false, true when rotation should occur, false when it shouldn't
   *
   * <br/><br/>
   *
   * The default configuration value puts forth a sensible refresh token rotation policy
   *   - only allows refresh tokens to be rotated (have their TTL prolonged by issuing a new one) for one year
   *   - otherwise always rotate public client tokens that are not sender-constrained
   *   - otherwise only rotate tokens if they're being used close to their expiration (>= 70% TTL passed)
   */
  rotateRefreshToken(ctx) {
    const { RefreshToken: refreshToken, Client: client } = ctx.oidc.entities;

    // cap the maximum amount of time a refresh token can be
    // rotated for up to 1 year, afterwards its TTL is final
    /* istanbul ignore if */
    if (refreshToken.totalLifetime() >= 365.25 * 24 * 60 * 60) {
      return false;
    }

    // rotate non sender-constrained public client refresh tokens
    if (client.tokenEndpointAuthMethod === 'none' && !refreshToken.isSenderConstrained()) {
      return true;
    }

    // rotate if the token is nearing expiration (it's beyond 70% of its lifetime)
    return refreshToken.ttlPercentagePassed() >= 70;
  },


  /*
   * whitelistedJWA
   *
   * description: Fine-tune the algorithms your provider will support by declaring algorithm
   *   values for each respective JWA use
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    tokenEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    introspectionEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    revocationEndpointAuthSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    idTokenSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    requestObjectSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    userinfoSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    introspectionSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
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
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    authorizationSigningAlgValues: [
      'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
    ],


    /*
     * whitelistedJWA.idTokenEncryptionAlgValues
     *
     * description: JWA algorithms the provider supports to wrap keys for ID Token encryption
     *
     * example: Supported values list
     * ```js
     * [
     *   // asymmetric RSAES based (note: RSA-OAEP-256 is only supported in node runtime >= 12.9.0)
     *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES key wrapping
     *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     *   // direct encryption
     *   'dir',
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
     *   // asymmetric RSAES based (note: RSA-OAEP-256 is only supported in node runtime >= 12.9.0)
     *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES key wrapping
     *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     *   // direct encryption
     *   'dir',
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
     *   // asymmetric RSAES based (note: RSA-OAEP-256 is only supported in node runtime >= 12.9.0)
     *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES key wrapping
     *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     *   // direct encryption
     *   'dir',
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
     *   // asymmetric RSAES based (note: RSA-OAEP-256 is only supported in node runtime >= 12.9.0)
     *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES key wrapping
     *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     *   // direct encryption
     *   'dir',
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
     *   // asymmetric RSAES based (note: RSA-OAEP-256 is only supported in node runtime >= 12.9.0)
     *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5',
     *   // asymmetric ECDH-ES based
     *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
     *   // symmetric AES key wrapping
     *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
     *   // symmetric PBES2 + AES
     *   'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
     *   // direct encryption
     *   'dir',
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


    /*
     * whitelistedJWA.dPoPSigningAlgValues
     *
     * description: JWA algorithms the provider supports to verify DPoP Proof JWTs with
     *
     * example: Supported values list
     * ```js
     * [
     *   'RS256', 'RS384', 'RS512',
     *   'PS256', 'PS384', 'PS512',
     *   'ES256', 'ES384', 'ES512',
     *   'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
     * ]
     * ```
     */
    dPoPSigningAlgValues: [
      'RS256', 'PS256', 'ES256', 'EdDSA',
    ],
  },
};

if (!runtimeSupport.EdDSA) {
  Object.values(DEFAULTS.whitelistedJWA).forEach((algs) => {
    const index = algs.indexOf('EdDSA');
    if (index !== -1) {
      algs.splice(index, 1);
    }
  });
}

/*
 * introspectionEndpointAuthMethods
 *
 * description: Array of Client Authentication methods supported by this OP's Introspection Endpoint.
 *   If no configuration value is provided the same values as for tokenEndpointAuthMethods will be
 *   used. Supported values list is the same as for tokenEndpointAuthMethods.
 */
DEFAULTS.introspectionEndpointAuthMethods = DEFAULTS.tokenEndpointAuthMethods;

/*
 * revocationEndpointAuthMethods
 *
 * description: Array of Client Authentication methods supported by this OP's Revocation Endpoint.
 *   If no configuration value is provided the same values as for tokenEndpointAuthMethods will be
 *   used. Supported values list is the same as for tokenEndpointAuthMethods.
 */
DEFAULTS.revocationEndpointAuthMethods = DEFAULTS.tokenEndpointAuthMethods;

module.exports = DEFAULTS;
