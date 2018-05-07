# oidc-provider CHANGELOG

Yay for [SemVer](http://semver.org/).

**Table of Contents**

<!-- TOC START min:2 max:2 link:true update:true -->
- [4.0.0](#400)
- [3.0.0](#300)
- [2.18.x](#218x)
- [2.17.0](#2170)
- [2.16.0](#2160)
- [2.15.0](#2150)
- [2.14.x](#214x)
- [2.13.x](#213x)
- [2.12.0](#2120)
- [2.11.x](#211x)
- [2.10.0](#2100)
- [2.9.x](#29x)
- [2.8.x](#28x)
- [2.7.x](#27x)
- [2.6.0](#260)
- [2.5.x](#25x)
- [2.4.x](#24x)
- [2.3.x](#23x)
- [2.2.x](#22x)
- [2.1.0](#210)
- [2.0.x](#20x)

<!-- TOC END -->

## 4.0.0
- [DIFF]
- A minimal version of node lts/carbon is required (>=8.9.0)
- **New configurations**
  - LRU-cache sizes
- **Session Changes**
  - stored sessions now have an `exp` property allowing the provider to ignore expired but
    still returned sessions
    - TODO: migration to avoid losing all sessions
- **Client Metadata**
  - null property values are no longer ignored
    - clients pushed through `#initialize()` must not submit properties with null values
    - clients stored via an adapter must be updated in your storage not to have null or
      null-deserialized values, alternatively you can update your adapter not to return these
      properties back to the provider
      ```js
      const _ = require('lodash');
      // your adapter implementation
      class MyAdapter {
        // ...
        async find(id) {
          // load entity properties and then drop the null properties if its a Client adapter instance
          // this is implementation specific
          const data = await DB.query(...);
          if (this.name === 'Client') {
            return _.omitBy(data, _.isNull);
          }
          return data;
        }
        // ...
      }
      ```

- **Client Authentication**
  - Errors related to authentication details parsing and format are now `400 Bad Request` and
    `invalid_request`. Errors related to actual authentication check are now `401 Unauthorized` and
    `invalid_client` with no details in the description.
    This means that errors related to client authentication will no longer leak details back to the
    client, instead the provider may be configured to get these errors from e.g.
    `provider.on('grant.error')` and provide the errors to clients out of bands.
    ```js
    function handleClientAuthErrors(err, { headers: { authorization }, oidc: { body, client } }) {
      if (err.statusCode === 401 && err.message === 'invalid_client') {
        // save error details out-of-bands for the client developers, `authorization`, `body`, `client`
        // are just some details available, you can dig in ctx object for more.
        console.log(err);
      }
    }
    provider.on('grant.error', handleClientAuthErrors);
    provider.on('introspection.error', handleClientAuthErrors);
    provider.on('revocation.error', handleClientAuthErrors);
    ```
  - added `WWW-Authenticate` response header to token endpoints when 401 is returned and Authorization
    scheme was used to authenticate and changed client authentication related errors to be `401 Unauthorized`
  - fixed several issues with token client authentication related to `client_id` lookup, it is no longer
    possible to:
    - submit multiple authentication mechanisms
    - send Authorization header to identify a `none` authentication method client
    - send both Authorization header and client_secret or client_assertion in the body

- **Other**
  - moved middleware handling missing optionally `redirect_uri` parameter case right after loading
    the client
  - `renderError` helper is now called with a third argument that's the actual Error instance.
  - bumped the semantic version of every dependency to the latest as of release
  - `features.pkce` now only enables `S256` by default, this is sufficient for most deployments. If
    `plain` is needed enable pkce with `{ features: { pkce: { supportedMethods: ['plain', 'S256'] } }`.
  - `client.backchannelLogout` no longer suppresses any errors, instead rejects the promise
  - token introspection endpoint no longer returns the wrong `token_type` claim - #189
    - to continue the support of this non-standardized claim from introspection you may register the following middleware
      ```js
      provider.use(async function introspectionTokenType(ctx, next) {
        await next();
        if (ctx._matchedRouteName === 'introspection') {
          const token = ctx.oidc.entities.AccessToken || ctx.oidc.entities.ClientCredentials || ctx.oidc.entities.RefreshToken;

          switch (token && token.kind) {
            case 'AccessToken':
              ctx.body.token_type = 'access_token';
              break;
            case 'ClientCredentials':
              ctx.body.token_type = 'client_credentials';
              break;
            case 'RefreshToken':
              ctx.body.token_type = 'refresh_token';
              break;
          }
        }
      });
      ```
  - fetched `request_uri` contents are no longer cached for 15 minutes default, cache headers are
    honoured and responses without one will fall off the LRU-Cache when this one is full
  - fixed failed client `jwks_uri` fetch requests to throw `invalid_client_metadata` rather then `server_error`
  - added `aud` to the introspection response if a token has one
  - `audiences` helper gets called with additional parameters `use` and `scope`
  - `audiences` helper `use` parameter is now in addition to existing `id_token` and signed `userinfo`
    cases `client_credentials` and `access_token`, this is useful for pushing additional audiences
    to an Access Token, these are now returned by token introspection and can be used when serializing
    an Access Token as a JWT
  - the provider will no longer use the first value from `acrValues` to denote a "session" like acr.
    In cases where acr is requested as a voluntary claim and no result is available this claim will
    not be returned.
    - to continue the support of the removed behaviour you can change the OIDCContext acr getter
      ```js
      const _ = require('lodash');
      const sessionAcr = '...';
      Object.defineProperty(provider.OIDCContext.prototype, 'acr', {
        get() {
          return _.get(this, 'result.login.acr', sessionAcr);
        },
      });
      ```

## 3.0.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.18.0...v3.0.0)
- fixed `client_secret_basic` requiring the username and password tokens to be `x-www-form-urlencoded`
  according to https://tools.ietf.org/html/rfc6749#section-2.3.1
  - NOTE: Although technically a fix, this is a breaking change for clients with client secrets that
    need to be encoded according to the standard and don't currently do so. A proper way of submitting
    client_id and client_secret using `client_secret_basic` is
    `Authorization: base64(formEncode(client_id):formEncode(client_secret))`. This is only becoming
    apparent for client ids and secrets with special characters that need encoding.

## 2.18.x
### 2.18.2
- re-released 2.18.0 as 2.18.2 following deprecation of 2.18.1

### 2.18.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.17.0...v2.18.0)
- added `ctx.oidc.entities` with all loaded model/entity instances during a given request
- added `cookies.keys` configuration option for KeyGrip key app passthrough
- added `#provider.setProviderSession` for setting provider session from outside of a regular context
- deprecated `#provider.setSessionAccountId` in favor of `#provider.setProviderSession`

## 2.17.0
- 2018-03-29 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.16.0...v2.17.0)
- fixed alternative verb routes to be named as well
- fixed default `interactionCheck` passing `/resume` when users click cancel or just navigate back to
  auth resume route
- added `client_update` and `client_delete` as named routes
- added `extraClientMetadata` configuration option that allows for custom client properties as well
  as for additional validations for existing properties to be defined
- when provider is configured with only `pairwise` subject type support then it is the
  client default and does not have to be explicitly provided anymore

## 2.16.0
- 2018-03-26 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.15.0...v2.16.0)
- supported PKCE code challenge methods are now configurable, use to i.e. disable `plain` for
  stricter OIDC profiles and new deployments where legacy clients without `S256` support aren't
  to be expected.
- added configuration validations for subjectTypes and pkce supportedMethods

## 2.15.0
- 2018-03-23 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.14.1...v2.15.0)
- added `provider.use((ctx, next) => {})` middleware support
- added `provider.listen(port_or_socket)`
- added attribute delegates `proxy`, `keys`, `env`, `subdomainOffset` from provider to the underlying
  koa app
- updated docs

## 2.14.x
### 2.14.1
- 2018-03-13 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.14.0...v2.14.1)
- bumped minimal `debug` dependency version due to its found vulnerability in lesser versions
- adjusted documentation on `refreshTokenRotation` configuration option
- adjusted documentation on TLS offloading

### 2.14.0
- 2018-03-05 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.13.1...v2.14.0)
- added current account id from OP session to interaction sessions
- added `provider.setSessionAccountId(req, id, [ts])` helper for setting OP
  session from other contexts, such as interrupted interactions or password
  reset flows.

## 2.13.x
### 2.13.1
- 2018-02-14 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.13.0...v2.13.1)
- `clientCacheDuration` no longer has any effect on static clients passed through the
  `#provider.initialize()` call

### 2.13.0
- 2018-01-29 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.12.0...v2.13.0)
- `#provider.Client.cacheClear([id])` can now optionally drop just one specific client from provider
  cache when provided its client_id

## 2.12.0
- 2018-01-24 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.11.2...v2.12.0)
- `findById` returned struct's `#claims()` method is now called with two parameters (use and
  scope) allowing to fine-tune the returned claims depending on the intended place for these claims.

## 2.11.x
### 2.11.2
- 2018-01-21 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.11.1...v2.11.2)
- aligned `oidc-provider:token` DEBUG format
- exposed client validation schema prototype under `provider.Client.Schema`

### 2.11.1
- 2018-01-17 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.11.0...v2.11.1)
- fixed a bug where non global logouts would not trigger back and front-channel logout features
  for the one client that gets logged out.
- added missing `backchannel.success` and `backchannel.error` events

### 2.11.0
- 2018-01-16 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.10.0...v2.11.0)
- added no-cache headers to userinfo responses
- added optional support for draft02 of [Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0-02.html)
  - enable with configuration `features.frontchannelLogout = true`;
  - adds new client properties `frontchannel_logout_uri` and `frontchannel_logout_session_required`
  - adds new discovery properties `frontchannel_logout_supported` and `frontchannel_logout_session_supported`
  - added `frontchannelLogoutPendingSource` helper for customizing the pending frontchannel web page
    HTML source

## 2.10.0
- 2018-01-15 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.9.2...v2.10.0)
- added `audiences` helper function to allow for pushing additional audiences to issued ID Tokens,
  this will additionally push an `azp` claim with the `client_id` value as per Core 1.0 spec defined
  ID Token validations.

## 2.9.x
### 2.9.2
- 2018-01-03 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.9.1...v2.9.2)
- added used http verb to error debug messages
- added a descriptive "method not allowed" error message

### 2.9.1
- 2017-12-18 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.9.0...v2.9.1)
- fixed `useRequest` to be a static method as documented

### 2.9.0
- 2017-12-14 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.8.3...v2.9.0)
- added and documented the optional use of [request](https://github.com/request/request)
  instead of [got](https://github.com/sindresorhus/got) for deployments requiring http(s) proxies
  to reach out to the internet wilderness

## 2.8.x
### 2.8.3
- 2017-12-12 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.8.2...v2.8.3)
- fixed token expires_in to be based off an overloadable BaseToken expiration() instance method
- fixed token introspection response for consumed tokens

### 2.8.2
- 2017-12-11 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.8.0...v2.8.2)
- changed grant_type requires to resolve oidc-provider loading through webpack

### 2.8.0
- 2017-12-05 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.7.2...v2.8.0)
- added provider `clockTolerance` option
- fixed clients with jwks_uri failing to be fetched blocking the initialize call
- fixed successful client keystore refresh after failed verification to pass
- bumped node-jose dependency

## 2.7.x
### 2.7.2
2017-11-30 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.6.0...v2.7.2)
- adjusted the client schema to ignore extra properties for disabled features
- fixed encrypted ID Tokens without a used alg (json payload) to have `cty` (content-type) `json`
- fixed unsigned ID Tokens missing `*_hash` properties
- `request_uri` response caching now also handles `expires` response headers

Note: 2.7.0 and 2.7.1 yanked for the bugs they introduced

## 2.6.0
- 2017-11-23 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.5.1...v2.6.0)
- added `scope` to successful token (authorization_code, refresh_token) responses
- updated dependencies (`got@8.x`, removed deprecated `buffer-equals-constant`)

## 2.5.x
### 2.5.1
- 2017-11-14 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.5.0...v2.5.1)
- fixed already authorized application_type=native prompt=none authorizations to be able to check
  if the authorization is still present
- bumped session management `jsSHA` cdn dependency version

### 2.5.0
- 2017-10-28 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.4.1...v2.5.0)
- added an option to return metadata alongside with interaction results, this metadata is then
  retrievable i.e. during the interactionCheck call. #164, #165
- added an option to return error instead of the standard interaction results, the provider
  will take this error (and error_description when provided) and resolve the authorization request
  with it. #167, #168
- fixed `Token#find()` swallowing `adapter#find` errors
- fixed introspection swallowing rethrown `adapter#find` errors

## 2.4.x
### 2.4.1
- 2017-10-12 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.4.0...v2.4.1)
- fixed token upsert expiration to respect token's instance expiration

### 2.4.0
- 2017-10-05 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.3.2...v2.4.0)
- added BaseToken public API, this API enables advanced users in search of features such as JWT-formatted
  Bearer tokens or not being able to reconstruct client token values from a DB backup to overload
  these methods and get those features.
- fixed keystore initialize method to allow for servers only supporting authorization flow not needing
  RS256 signature key
- fixed token introspection disclosing details for expired but found tokens
- fixed exception during token introspection auth `none` clients looking up non-existing tokens

## 2.3.x
### 2.3.2
- 2017-09-25 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.3.1...v2.3.2)
- fixed `interactionFinished`, `interactionDetails` and `Session#find` expecting an id retrieved
  from a cookie. When not found will throw.

### 2.3.1
- 2017-09-15 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.3.0...v2.3.1)
- fixed `devInteractions` reported with the same grant `uuid`

### 2.3.0
- 2017-09-11 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.2.1...v2.3.0)
- added `s_hash` support for ID Tokens returned by authorization endpoint
- added Request Object symmetrical encryption support
- fixed PBES2 encryption to use client_secret derived symmetrical key instead of its full octet value
- fixed `claims` parameter handling when part of a Request object as an object
- removed bugged? and/or previously not working `A(128|192|256)GCMKW` symmetrical encryption algs

## 2.2.x
### 2.2.1
- 2017-09-09 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.2.0...v2.2.1)
- fixed encrypted parameters incorrectly assumed as signed (request object asymmetrical encryption)

### 2.2.0
- 2017-08-27 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.1.0...v2.2.0)
- added a `clientCacheDuration` option (defaults to `Infinity`), this option defines the time a client
  configuration loaded from an adapter will be kept in cache before being loaded again with the next
  request
- removed `valid-url` dependency in favor of STDLIB's WHATWG `url.URL`

## 2.1.0
- 2017-08-04 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.0.1...v2.1.0)
- added a third parameter for `findById` helper, when `findById` is used in relation to an access
  token or an authorization code the token instance will be passed
- added `ctx.oidc.signed` with an array of parameter names which were received using a signed or
  encrypted request/Uri parameter.
- `signed` array of strings is available in the short lived session for interactions
- added basic sequelize adapter example
- fixed a bug where extraParams weren't recognized when part of a `request` or `request_uri` parameters
- fixed a bug where client credential and refresh token adapter instances were used even if these
  grants/tokens weren't enabled
- fixed a bug which allowed for non-enabled scopes to be added in client_credential grants

## 2.0.x
### 2.0.1
- 2017-08-04 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.0.0...v2.0.1)
- fixed infinite interactionCheck loop for `application_type=native` clients

### 2.0.0
*Breaking Changes*
- **oidc-provider now requires node v8.0.0 or higher for ES2015, async function and utils.promisify support**
- **internal koa (and related) dependencies updated to their respective 'next' or koa2 middleware
  compatible versions**
- adapter must now be passed into `#initialize()`
- helper functions which returned or accepted generators will no longer work, use async functions
- helper functions no longer have koa ctx bound to `this`, instead their signature is changed
- interactionUrl helper signature changed to (ctx, interaction) **and is now awaited**
- renderError helper signature changed to (ctx, error) **and is now awaited**
- uniqueness helper signature changed to (ctx, jti, expiresAt)
- interactionCheck helper signature changed to (ctx)
- default interactionCheck helper requires all native application client authorizations to pass
  through interactions
- findById helper signature changed to (ctx, accountId)
- `postLogoutRedirectUri` configuration option is now a helper function and is awaited to
- default acrValues configuration option is now empty, if you used the old values `['0', '1', '2']`,
  you must configure the value explicitly
- `ctx.prompted` renamed to more descriptive `ctx.promptPending`
- **default refreshTokenRotation changed from 'none' to 'rotateAndConsume'**
- pkce.skipClientAuth removed, native clients not willing to submit secrets should be registered
  with method none
- **`features.requestUri` enabled by default with requireRequestUriRegistration**
- **`features.oauthNativeApps` enabled by default**
- `features.oauthNativeApps` automatically enables `features.pkce` with `{ forcedForNative: true }`
- **interaction details no longer utilize cookies to store the details and request parameters,
  short lived sessions are created and maintained via the adapter instead**
- **Integrity keystore is no longer used, random strings are used to generate a lengthy token,
  a none signed JWT is used to store the metadata, keeping the datasets the same as 1.x**
- interaction helper `provider#interactionDetails` now returns a Promise, it reads the short lived
  session id and loads the details using your adapter
- interaction helper `provider.interactionFinished` now returns a Promise, it reads the short lived
  session id and stores the interaction results there
- default token TTLs shortened
- Request Object `iss` (issuer) and `aud` (audience) values are now being validated to be equal to
  Client's identifier (`iss`) and the OP Issuer identifier (`aud`) when present in a Request Object

*New features*
- `static` function named `connect` can now be present on an Adapter prototype, this will be awaited
  during initialization, use to establish the necessary adapter connections
- introspection and revocation endpoint authentication now has dedicated settings and properties,
  unless specific settings for those are provided they default to what's provided for token_endpoint
  equivalents, this allows for fine-tuning while not disrupting existing behavior
- new client metadata supported:
  - introspection_endpoint_auth_method
  - introspection_endpoint_auth_signing_alg
  - revocation_endpoint_auth_method
  - revocation_endpoint_auth_signing_alg
- new configuration properties:
  - introspectionEndpointAuthMethods
  - introspectionEndpointAuthSigningAlgValues
  - unsupported.introspectionEndpointAuthSigningAlgValues
  - revocationEndpointAuthMethods
  - revocationEndpointAuthSigningAlgValues
  - unsupported.revocationEndpointAuthSigningAlgValues
- new discovery properties:
  - introspection_endpoint_auth_methods_supported
  - introspection_endpoint_auth_signing_alg_values_supported
  - revocation_endpoint_auth_methods_supported
  - revocation_endpoint_auth_signing_alg_values_supported
