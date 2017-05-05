# oidc-provider CHANGELOG

Yay for [SemVer](http://semver.org/).

**Table of Contents**

<!-- TOC START min:2 max:2 link:true update:true -->
  - [Version 2.0.0](#version-200)
  - [Versions 1.x](#versions-1x)

<!-- TOC END -->

## Version 2.0.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.15.3...v2.0.0)

*Breaking Changes*
- oidc-provider now requires node v7.6.0 or higher for ES2015 and async function support
- internal koa (and related) dependencies updated to their respective 'next' or koa2 middleware
  compatible versions
- adapter is now a property passed into `#initialize()`, adapter properties in configuration will
  result in a rejected initialize
- helper functions which returned or accepted generators will no longer work, use async functions instead
- default acrValues configuration option is now empty, if you used the old values `['0', '1', '2']`,
  you must configure the value explicitly
- helper functions no longer have koa ctx bound to `this`, instead their signature is changed
- interactionUrl helper signature changed to (ctx, interaction) **and is now awaited**
- renderError helper signature changed to (ctx, error) **and is now awaited**
- uniqueness helper signature changed to (ctx, jti, expiresAt)
- interactionCheck helper signature changed to (ctx)
- findById helper signature changed to (ctx, accountId)
- `postLogoutRedirectUri` configuration option is now a helper function and is awaited to (was a string property)
- `ctx.prompted` renamed to more descriptive `ctx.promptPending`
- default refreshTokenRotation changed from 'none' to 'rotateAndConsume'
- pkce.skipClientAuth removed, native clients not willing to submit secrets should be registered
  with method none

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

*Fixes*
- fixed logout buttons in browsers not supporting "form" attribute
- fixed logout submit when there was is no session

## Versions 1.x
### Version 1.15.0
#### Version 1.15.7
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.15.6...v1.15.7)
- Native Apps BCP draft reference updated, no change in implementation
- allow introspection and revocation w/o auth for native clients when pkce.skipClientAuth is enabled
- fixed client post_logout_redirect_uris validation to allow all urls
- fixed token_endpoint_auth_method=none to how it should be (skip auth instead of forbid use)
- fixed a 500 from token_endpoint when a valid(whitelisted) but invalid(d'oh) grant_type=implicit
  is submitted

#### Version 1.15.6
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.15.4...v1.15.6)
- bumped node-jose dependency to avoid github tar.gz dependencies
- fix: allow id_token_signed_response_alg=none for code+token response_type

#### Version 1.15.4
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.15.3...v1.15.4)
- fixed the provider removing middlewares from an upstream app (mounted case scenario)

#### Version 1.15.3
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.15.2...v1.15.3)
- redone client validations concerning response_types, grant_types and redirect_uris to allow niche
  client setups (i.e. custom or client_credential grant only)

#### Version 1.15.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.15.1...v1.15.2)
- bumped minimum node-jose version to cover http://blog.intothesymmetry.com/2017/03/critical-vulnerability-in-json-web.html

#### Version 1.15.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.15.0...v1.15.1)
- fixed full logout sessions still being upserted after their removal
- fixed partial logout sessions still having the logout details

#### Version 1.15.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.14.0...v1.15.0)
- fix: 'none' token_endpoint_auth_method clients can still use code flow with PKCE.
- Native Apps BCP draft updated from draft07 to draft09
  - custom uri schemes not containing a period character (".") will be rejected

  > For Custom URI scheme based redirects, authorization servers SHOULD
  > enforce the requirement in Section 7.1 that clients use reverse
  > domain name based schemes.  At a minimum, any scheme that doesn't
  > contain a period character ("."), SHOULD be rejected.

### Version 1.14.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.13.0...v1.14.0)
- backwards compatible default-on pkce feature flag added so now pkce support can be disabled
- forcedForNative flag for pkce added to force native clients using hybrid or code flow to use pkce
- skipClientAuth flag for pkce added to allow skipping basic or post client auth for `authorization_code`
  and `refresh_token` grants (to be in line with default AppAuth sdk behavior)
- loosened code flow only web clients redirect_uris restriction
- removed cookies dependency
- locked dependencies below semver >= 1.0.0 with ~ instead of ^

### Version 1.13.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.12.1...v1.13.0)
- added `end_session.success` event
- added a warning for detected untrusted `x-forwarded-*` headers

### Version 1.12.0
#### Version 1.12.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.12.0...v1.12.1)
- fixed request parameter containing claims parameter being an object (#78)

#### Version 1.12.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.11.0...v1.12.0)
- Added a detection of session management cookies being blocked as a result of a user-agent optout
  and added appropriate handling to mitigate resulting incorrect `changed` states

### Version 1.11.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.10.2...v1.11.0)
- Updated implementation of Back-Channel Logout from draft03 to draft04
  - Logout Token's event claim is now an object with `http://schemas.openid.net/event/backchannel-logout`
    as a member name.
- Session Management and Native Apps BCP draft references updated, no change in implementations

### Version 1.10.0
#### Version 1.10.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.10.1...v1.10.2)
- fixed state parameter pass-through for Session Management end_session endpoint

#### Version 1.10.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.10.0...v1.10.1)
- fixed expected aud value in private_key_jwt and client_secret_jwt client authentication
  for introspection_endpoint and revocation_endpoint

#### Version 1.10.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.9.1...v1.10.0)
- added the option to change used cookie names
- fixed cleanup of OP cookies after interaction and logout
- fixed logout form action in mounted OP scenarios

### Version 1.9.0
#### Version 1.9.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.9.0...v1.9.1)
- fixed discovery `token_introspection_endpoint (kept until 2.0) -> introspection_endpoint (added)`
- fixed discovery `token_revocation_endpoint (kept until 2.0) -> revocation_endpoint (added)`
- fixed default response mode for `token` response_type to be also `fragment`
- added missing discovery `code_challenge_methods_supported`

#### Version 1.9.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.6...v1.9.0)
- ensure x-frame-options and content-security-policy headers from tools like helmet do not interfere
  with `check_session_iframe`, see options to disable the behavior if you know what you're actually
  doing with those headers
- fixed client validation not checking `token_endpoint_auth_signing_alg` values

### Version 1.8.0
#### Version 1.8.6
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.3...v1.8.6)
- fixed unchanged interactionUrl with devInteractions disabled

#### Version 1.8.3
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.2...v1.8.3)
- fixed Client#find to always load a freshly stored client in dynamic registration reads and updates

#### Version 1.8.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.0...v1.8.2)
- fixed unchanged interactionUrl in mounted OP scenarios

#### Version 1.8.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.7.0...v1.8.0)
- fixed scenarios where oidc-provider is mounted in an express application
- documented recommended mounting approach for both koa and express
- added registration feature option to overwrite the generated client_id format
- added `refreshTokenRotation` configuration option, default 'none', optional 'rotateAndConsume'
- added `provider.Client.cacheClear()` method to allow wiping the internal client cache programmatically

### Version 1.7.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.6.0...v1.7.0)
- Added new interaction helpers `provider#interactionDetails` and `provider#interactionFinished`
- Deprecated `provider#resume` in favor of the new helper
- Added Fine-tuning supported algorithms
- Moved final interaction check to configuration to allow for it's customization
- Fixed removing of acr from claims_supported when passed an empty array in configuration

### Version 1.6.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.5.2...v1.6.0)
- Deprecated `require('oidc-provider').Provider` export in favor of just `require('oidc-provider')`
- Added presence and format validations for the Provider constructor Issuer Identifier parameter

### Version 1.5.0
#### Version 1.5.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.5.1...v1.5.2)
- fixed www-authenticate header value for html rendered userinfo unauthorized

#### Version 1.5.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.5.0...v1.5.1)
- fixed a 500 Server Error case on end_session when no `_state` cookies were matched

#### Version 1.5.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.4.2...v1.5.0)
- added debugging utility via [debug][debug-link]

### Version 1.4.0
#### Version 1.4.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.4.1...v1.4.2)
- fixed an issue for provider instances with upstream already parsing the request body

#### Version 1.4.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.4.0...v1.4.1)
- fixed custom uri scheme native clients hostname validations

#### Version 1.4.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.3.0...v1.4.0)
- added optional support for [OAuth 2.0 for Native Apps BCP - draft 06][https://tools.ietf.org/html/draft-ietf-oauth-native-apps-06]
  - enable with configuration `features.oauthNativeApps = true`;
- offline_access scope is now ignored when consent prompt is missing instead of being rejected as invalid_request
- unrecognized authentication requests scopes are now ignored instead of being rejected as invalid_request
- renamed the refreshToken feature flag to a more appropriate alwaysIssueRefresh

### Version 1.3.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.2.0...v1.3.0)
- added optional Registration Access Token rotation strategy for Dynamic Client Registration Management Protocol
- added request ctx bind to findById

### Version 1.2.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.1.0...v1.2.0)
- account's `#claims()` can now return a promise
- when acrValues passed in are empty the claim is not published as supported, the neither is
  acr_values_supported as it would be an empty array anyway

### Version 1.1.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.3...v1.1.0)
- resolved #37 - authorization endpoint can now be configured with additional whitelisted parameters
- amr claim handling (similar to acr)
- defining custom claims with a new array syntax (in addition, prev. syntax still works)
- scope names from claims are automatically added to the published scopes_supported list

### Version 1.0.0
#### Version 1.0.3
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.2...v1.0.3)
- fixes #36 - devInteractions feature rendering when mounted
- ensure server_error is emitted for actions without a specific eventName

#### Version 1.0.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.1...v1.0.2)
- Fixed acr claim behavior - only the authentication request ACR was negotiated for should have
  higher than the fallback value
- Fixed server_error when acr was requested via claims parameter with null value

#### Version 1.0.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.0...v1.0.1)
- Updated uuid dependency

#### Version 1.0.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v0.11.4...v1.0.0)

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
