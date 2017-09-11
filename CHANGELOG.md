# oidc-provider CHANGELOG

Yay for [SemVer](http://semver.org/).

**Table of Contents**

<!-- TOC START min:2 max:3 link:true update:true -->
  - [2.3.0](#230)
  - [2.2.x](#22x)
    - [2.2.1](#221)
    - [2.2.0](#220)
  - [2.1.0](#210)
  - [2.0.x](#20x)
    - [2.0.1](#201)
    - [2.0.0](#200)
  - [^1.0.0](#100)
    - [1.15.x](#115x)
    - [1.14.x](#114x)
    - [1.13.x](#113x)
    - [1.12.x](#112x)
    - [1.11.x](#111x)
    - [1.10.x](#110x)
    - [1.9.x](#19x)
    - [1.8.x](#18x)
    - [1.7.x](#17x)
    - [1.6.x](#16x)
    - [1.5.x](#15x)
    - [1.4.x](#14x)
    - [1.3.x](#13x)
    - [1.2.x](#12x)
    - [1.1.x](#11x)
    - [1.0.x](#10x)

<!-- TOC END -->

## 2.3.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.2.1...v2.3.0)
- added `s_hash` support for ID Tokens returned by authorization endpoint
- added Request Object symmetrical encryption support
- fixed PBES2 encryption to use client_secret derived symmetrical key instead of its full octet value
- fixed `claims` parameter handling when part of a Request object as an object
- removed bugged? and/or previously not working `A(128|192|256)GCMKW` symmetrical encryption algs
- removed support for discontinued OAuth 2.0 Mix-Up Mitigation (was experimental)

## 2.2.x
### 2.2.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.2.0...v2.2.1)
- fixed encrypted parameters incorrectly assumed as signed (request object asymmetrical encryption)

### 2.2.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.1.0...v2.2.0)
- added a `clientCacheDuration` option (defaults to `Infinity`), this option defines the time a client
  configuration loaded from an adapter will be kept in cache before being loaded again with the next
  request
- removed `valid-url` dependency in favor of STDLIB's WHATWG `url.URL`

## 2.1.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.0.1...v2.1.0)
- added a third parameter for `findById` helper, when `findById` is used in relation to an access
  token or an authorization code the token instance will be passed
- added `ctx.oidc.signed` with an array of parameter names which were received using a signed or
  encrypted request/Uri parameter.
- `signed` array of strings is available in the short lived session for interactions
- added optional support for [OAuth 2.0 Mix-Up Mitigation - draft 01](https://tools.ietf.org/html/draft-ietf-oauth-mix-up-mitigation-01)
- added basic sequelize adapter example
- fixed a bug where extraParams weren't recognized when part of a `request` or `request_uri` parameters
- fixed a bug where client credential and refresh token adapter instances were used even if these
  grants/tokens weren't enabled
- fixed a bug which allowed for non-enabled scopes to be added in client_credential grants

## 2.0.x
### 2.0.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.0.0...v2.0.1)
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

## ^1.0.0
### 1.15.x
- fixed clients schema validation for clients with custom ROPC grant and refresh
- fixed JWT signing of utf8 containing input
- fixed subsequent refresh token refresh with pkce.skipClientAuth = true
- fixed revocation response body to be empty
- fixed revocation response when invalid inputs occur, unsupported_token_type may not happen since
  token type support for revocation does not support defining which tokens are supported and which
  arent
- Native Apps BCP draft reference updated, no change in implementation
- allow introspection and revocation w/o auth for native clients when pkce.skipClientAuth is enabled
- fixed client post_logout_redirect_uris validation to allow all urls
- fixed token_endpoint_auth_method=none to how it should be (skip auth instead of forbid use)
- fixed a 500 from token_endpoint when a valid(whitelisted) but invalid(d'oh) grant_type=implicit
  is submitted
- bumped node-jose dependency to avoid github tar.gz dependencies
- fix: allow id_token_signed_response_alg=none for code+token response_type
- fixed the provider removing middlewares from an upstream app (mounted case scenario)
- redone client validations concerning response_types, grant_types and redirect_uris to allow niche
  client setups (i.e. custom or client_credential grant only)
- bumped minimum node-jose version to cover http://blog.intothesymmetry.com/2017/03/critical-vulnerability-in-json-web.html
- fixed full logout sessions still being upserted after their removal
- fixed partial logout sessions still having the logout details
- fix: 'none' token_endpoint_auth_method clients can still use code flow with PKCE.
- Native Apps BCP draft updated from draft07 to draft09 (custom uri schemes not containing a period character (".") will be rejected)

### 1.14.x
- backwards compatible default-on pkce feature flag added so now pkce support can be disabled
- forcedForNative flag for pkce added to force native clients using hybrid or code flow to use pkce
- skipClientAuth flag for pkce added to allow skipping basic or post client auth for `authorization_code`
  and `refresh_token` grants (to be in line with default AppAuth sdk behavior)
- loosened code flow only web clients redirect_uris restriction
- removed cookies dependency
- locked dependencies below semver >= 1.0.0 with ~ instead of ^

### 1.13.x
- added `end_session.success` event
- added a warning for detected untrusted `x-forwarded-*` headers

### 1.12.x
- fixed request parameter containing claims parameter being an object (#78)
- Added a detection of session management cookies being blocked as a result of a user-agent optout
  and added appropriate handling to mitigate resulting incorrect `changed` states

### 1.11.x
- Updated implementation of Back-Channel Logout from draft03 to draft04
  - Logout Token's event claim is now an object with `http://schemas.openid.net/event/backchannel-logout`
    as a member name.
- Session Management and Native Apps BCP draft references updated, no change in implementations

### 1.10.x
- fixed state parameter pass-through for Session Management end_session endpoint
- fixed expected aud value in private_key_jwt and client_secret_jwt client authentication
  for introspection_endpoint and revocation_endpoint
- added the option to change used cookie names
- fixed cleanup of OP cookies after interaction and logout
- fixed logout form action in mounted OP scenarios

### 1.9.x
- fixed discovery `token_introspection_endpoint (kept until 2.0) -> introspection_endpoint (added)`
- fixed discovery `token_revocation_endpoint (kept until 2.0) -> revocation_endpoint (added)`
- fixed default response mode for `token` response_type to be also `fragment`
- added missing discovery `code_challenge_methods_supported`
- ensure x-frame-options and content-security-policy headers from tools like helmet do not interfere
  with `check_session_iframe`, see options to disable the behavior if you know what you're actually
  doing with those headers
- fixed client validation not checking `token_endpoint_auth_signing_alg` values

### 1.8.x
- fixed unchanged interactionUrl with devInteractions disabled
- fixed Client#find to always load a freshly stored client in dynamic registration reads and updates
- fixed unchanged interactionUrl in mounted OP scenarios
- fixed scenarios where oidc-provider is mounted in an express application
- documented recommended mounting approach for both koa and express
- added registration feature option to overwrite the generated client_id format
- added `refreshTokenRotation` configuration option, default 'none', optional 'rotateAndConsume'
- added `provider.Client.cacheClear()` method to allow wiping the internal client cache programmatically

### 1.7.x
- Added new interaction helpers `provider#interactionDetails` and `provider#interactionFinished`
- Deprecated `provider#resume` in favor of the new helper
- Added Fine-tuning supported algorithms
- Moved final interaction check to configuration to allow for it's customization
- Fixed removing of acr from claims_supported when passed an empty array in configuration

### 1.6.x
- Deprecated `require('oidc-provider').Provider` export in favor of just `require('oidc-provider')`
- Added presence and format validations for the Provider constructor Issuer Identifier parameter

### 1.5.x
- fixed www-authenticate header value for html rendered userinfo unauthorized
- fixed a 500 Server Error case on end_session when no `_state` cookies were matched
- added debugging utility via [debug][debug-link]

### 1.4.x
- fixed an issue for provider instances with upstream already parsing the request body
- fixed custom uri scheme native clients hostname validations
- added optional support for [OAuth 2.0 for Native Apps BCP - draft 06][https://tools.ietf.org/html/draft-ietf-oauth-native-apps-06]
  - enable with configuration `features.oauthNativeApps = true`;
- offline_access scope is now ignored when consent prompt is missing instead of being rejected as invalid_request
- unrecognized authentication requests scopes are now ignored instead of being rejected as invalid_request
- renamed the refreshToken feature flag to a more appropriate alwaysIssueRefresh

### 1.3.x
- added optional Registration Access Token rotation strategy for Dynamic Client Registration Management Protocol
- added request ctx bind to findById

### 1.2.x
- account's `#claims()` can now return a promise
- when acrValues passed in are empty the claim is not published as supported, the neither is
  acr_values_supported as it would be an empty array anyway

### 1.1.x
- resolved #37 - authorization endpoint can now be configured with additional whitelisted parameters
- amr claim handling (similar to acr)
- defining custom claims with a new array syntax (in addition, prev. syntax still works)
- scope names from claims are automatically added to the published scopes_supported list

### 1.0.x
- fixes #36 - devInteractions feature rendering when mounted
- ensure server_error is emitted for actions without a specific eventName
- Fixed acr claim behavior - only the authentication request ACR was negotiated for should have
  higher than the fallback value
- Fixed server_error when acr was requested via claims parameter with null value
- Updated uuid dependency

Notable changes:
- feature flag devInteractions, enabled by default, complementing the default configuration
  enables to experiment with just the required library, no need to clone the example anymore
  to get working interactions
  - a console notice is in place to let developers know the feature is enabled
- `provider#initialize` to pass integrity and cert keystores as well as pre-set client
  configurations
  - removed the option to add clients programmatically during runtime (outside of dynamic
    registration)
- `offline_access` scope ignored for Implicit Flow (def. Core 1.0 - section Offline Access)
- default `uniqueness` works as intended for single-process deployments
- provider.OAuthToken deprecated in favor of provider.BaseToken

Bugfixes:
- client validation: https URI scheme only uris now validated for https scheme (initiate_login_uri,
  sector_identifier_uri, request_uris)
- client validation: https URI scheme is now forbidden for native clients
- client validation: http URI scheme is now forbidden for implicit web clients

[debug-link]: https://github.com/visionmedia/debug
