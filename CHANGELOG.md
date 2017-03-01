# oidc-provider CHANGELOG

Yay for [SemVer](http://semver.org/).

**Table of Contents**

<!-- TOC START min:2 max:2 link:true update:true -->
  - [Version 2.x](#version-2x)
  - [Version 1.14.0](#version-1140)
  - [Version 1.13.0](#version-1130)
  - [Version 1.12.0](#version-1120)
  - [Version 1.11.0](#version-1110)
  - [Version 1.10.0](#version-1100)
  - [Version 1.9.0](#version-190)
  - [Version 1.8.0](#version-180)
  - [Version 1.7.0](#version-170)
  - [Version 1.6.0](#version-160)
  - [Version 1.5.0](#version-150)
  - [Version 1.4.0](#version-140)
  - [Version 1.3.0](#version-130)
  - [Version 1.2.0](#version-120)
  - [Version 1.1.0](#version-110)
  - [Version 1.0.0](#version-100)
  - [Migrating from 0.11.x to 1.0.0](#migrating-from-011x-to-100)
  - [pre 1.x changelog](#pre-1x-changelog)

<!-- TOC END -->

## Version 2.x
- [DIFF](https://github.com/panva/node-oidc-provider/compare/master...next)

## Version 1.14.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.13.0...v1.14.0)
- backwards compatible default-on pkce feature flag added so now pkce support can be disabled
- forcedForNative flag for pkce added to force native clients using hybrid or code flow to use pkce
- skipClientAuth flag for pkce added to allow skipping basic or post client auth for `authorization_code`
  and `refresh_token` grants (to be in line with default AppAuth sdk behavior)
- loosened coe flow only web clients redirect_uris restriction
- removed cookies dependency
- locked dependencies below semver >= 1.0.0 with ~ instead of ^

## Version 1.13.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.12.1...v1.13.0)
- added `end_session.success` event
- added a warning for detected untrusted `x-forwarded-*` headers

## Version 1.12.0
### Version 1.12.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.12.0...v1.12.1)
- fixed request parameter containing claims parameter being an object (#78)

### Version 1.12.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.11.0...v1.12.0)
- Added a detection of session management cookies being blocked as a result of a user-agent optout
  and added appropriate handling to mitigate resulting incorrect `changed` states

## Version 1.11.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.10.2...v1.11.0)
- Updated implementation of Back-Channel Logout from draft03 to draft04
  - Logout Token's event claim is now an object with `http://schemas.openid.net/event/backchannel-logout`
    as a member name.
- Session Management and Native Apps BCP draft references updated, no change in implementations

## Version 1.10.0
### Version 1.10.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.10.1...v1.10.2)
- fixed state parameter pass-through for Session Management end_session endpoint

### Version 1.10.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.10.0...v1.10.1)
- fixed expected aud value in private_key_jwt and client_secret_jwt client authentication
  for introspection_endpoint and revocation_endpoint

### Version 1.10.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.9.1...v1.10.0)
- added the option to change used cookie names
- fixed cleanup of OP cookies after interaction and logout
- fixed logout form action in mounted OP scenarios

## Version 1.9.0
### Version 1.9.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.9.0...v1.9.1)
- fixed discovery `token_introspection_endpoint (kept until 2.0) -> introspection_endpoint (added)`
- fixed discovery `token_revocation_endpoint (kept until 2.0) -> revocation_endpoint (added)`
- fixed default response mode for `token` response_type to be also `fragment`
- added missing discovery `code_challenge_methods_supported`

### Version 1.9.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.6...v1.9.0)
- ensure x-frame-options and content-security-policy headers from tools like helmet do not interfere
  with `check_session_iframe`, see options to disable the behavior if you know what you're actually
  doing with those headers
- fixed client validation not checking `token_endpoint_auth_signing_alg` values

## Version 1.8.0
### Version 1.8.6
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.3...v1.8.6)
- fixed unchanged interactionUrl with devInteractions disabled

### Version 1.8.3
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.2...v1.8.3)
- fixed Client#find to always load a freshly stored client in dynamic registration reads and updates

### Version 1.8.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.8.0...v1.8.2)
- fixed unchanged interactionUrl in mounted OP scenarios

### Version 1.8.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.7.0...v1.8.0)
- fixed scenarios where oidc-provider is mounted in an express application
- documented recommended mounting approach for both koa and express
- added registration feature option to overwrite the generated client_id format
- added `refreshTokenRotation` configuration option, default 'none', optional 'rotateAndConsume'
- added `provider.Client.cacheClear()` method to allow wiping the internal client cache programmatically

## Version 1.7.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.6.0...v1.7.0)
- Added new interaction helpers `provider#interactionDetails` and `provider#interactionFinished`
- Deprecated `provider#resume` in favor of the new helper
- Added Fine-tuning supported algorithms
- Moved final interaction check to configuration to allow for it's customization
- Fixed removing of acr from claims_supported when passed an empty array in configuration

## Version 1.6.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.5.2...v1.6.0)
- Deprecated `require('oidc-provider').Provider` export in favor of just `require('oidc-provider')`
- Added presence and format validations for the Provider constructor Issuer Identifier parameter

## Version 1.5.0
### Version 1.5.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.5.1...v1.5.2)
- fixed www-authenticate header value for html rendered userinfo unauthorized

### Version 1.5.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.5.0...v1.5.1)
- fixed a 500 Server Error case on end_session when no `_state` cookies were matched

### Version 1.5.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.4.2...v1.5.0)
- added debugging utility via [debug][debug-link]

## Version 1.4.0
### Version 1.4.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.4.1...v1.4.2)
- fixed an issue for provider instances with upstream already parsing the request body

### Version 1.4.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.4.0...v1.4.1)
- fixed custom uri scheme native clients hostname validations

### Version 1.4.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.3.0...v1.4.0)
- added optional support for [OAuth 2.0 for Native Apps BCP - draft 06][https://tools.ietf.org/html/draft-ietf-oauth-native-apps-06]
  - enable with configuration `features.oauthNativeApps = true`;
- offline_access scope is now ignored when consent prompt is missing instead of being rejected as invalid_request
- unrecognized authentication requests scopes are now ignored instead of being rejected as invalid_request
- renamed the refreshToken feature flag to a more appropriate alwaysIssueRefresh

## Version 1.3.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.2.0...v1.3.0)
- added optional Registration Access Token rotation strategy for Dynamic Client Registration Management Protocol
- added request ctx bind to findById

## Version 1.2.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.1.0...v1.2.0)
- account's `#claims()` can now return a promise
- when acrValues passed in are empty the claim is not published as supported, the neither is
  acr_values_supported as it would be an empty array anyway

## Version 1.1.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.3...v1.1.0)
- resolved #37 - authorization endpoint can now be configured with additional whitelisted parameters
- amr claim handling (similar to acr)
- defining custom claims with a new array syntax (in addition, prev. syntax still works)
- scope names from claims are automatically added to the published scopes_supported list

## Version 1.0.0
### Version 1.0.3
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.2...v1.0.3)
- fixes #36 - devInteractions feature rendering when mounted
- ensure server_error is emitted for actions without a specific eventName

### Version 1.0.2
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.1...v1.0.2)
- Fixed acr claim behavior - only the authentication request ACR was negotiated for should have
  higher than the fallback value
- Fixed server_error when acr was requested via claims parameter with null value

### Version 1.0.1
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v1.0.0...v1.0.1)
- Updated uuid dependency

### Version 1.0.0
- [DIFF](https://github.com/panva/node-oidc-provider/compare/v0.11.4...v1.0.0)
- Please see [1.x migration](#migrating-from-011x-to-100) to update your 0.11.x deployment into 1.x.

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

## Migrating from 0.11.x to 1.0.0

1. set configuration option feature.`devInteractions` to `false`
2. resolve provider`#initialize()` before accessing provider`.app` or provider`.callback`
3. move configuration.`keystore`, `integrity` and `clients` to provider`#initialize()`
4. change all your provider#`addClient` calls to one provider`#initialize({ clients: [ {}, {}, ... ] })`

## pre 1.x changelog

    4. Major version zero (0.y.z) is for initial development. Anything may change at any time.
       The public API should not be considered stable.

    5. Version 1.0.0 defines the public API.

- https://github.com/panva/node-oidc-provider/compare/v0.10.2...v0.11.0
  - BREAKING: ALL previously issued tokens are incompatible with the new version, the length of the
  tokens is now shorter and does not contain any information about the token context or type, this
  is to make space for Token Integrity feature that brings much faster, cheaper token generation.
  [Read More](#token-integrity)
  - fix: revocation is only possible for client's OWN tokens
  - change: end_session now with user confirmation and optionally without id_token_hint (as per spec)
  - change: session management individual states now in individual cookies rather than one
  - change: configuration.timeouts is removed
  - change: Back-Channel Logout draft implementation bumped from 02 to 03
  - change: dynamic registration related events now include the relevant CRUD verb
  - change: when remember is missing from the resume cookie a transient cookie is issued instead of
  no cookie at all
  - change: errors now use the renderError helper when viewed in a browser environment
  - change: interactionUrl has now ctx bound as this, and as parameter gets the interaction details
  - change: uniqueness has now ctx bound as this
  - change: renderError has now ctx bound as this
  - change: default cookies not signed (faster up and running development)
  - added: Setting defaultHttpOptions on provider instance for external http requests
  - added: Initial Access Token for Dynamic Registration (either fixed string or backed by adapter)
  - added: Update and Delete from RFC7592 - OAuth 2.0 Dynamic Client Registration Management
  Protocol
  - added: Back-Channel Logout session now supported
    - sid claim is available in id tokens when backchannelLogout is enabled
    - unique sid is now stored for each encountered client in a session
  - change: session model
    - new property `authorizations` of type Object now stored with the session, currently can only
    contain sid key, in the future will contain more
  - change: interaction is now requested first time a client is encountered (strategies for this
  coming later)
  - DEPRECATION: provider.get('ModelName') now deprecated, instead use provider.ModelName, ie.
  provider.AccessToken
  - DEPRECATION: provider.addKey now deprecated, prepare your keystores before new call and pass it
  via configuration.keystore
- https://github.com/panva/node-oidc-provider/compare/v0.10.0...0.10.2
  - fix: push nonce from code to refresh token and then id_token upon refresh
  - fix: RFC6749 4.1.2.1 - missing, unrecognized, invalid client_id and redirect_uri handling (consistent no redirect)
- https://github.com/panva/node-oidc-provider/compare/v0.9.0...v0.10.0
  - added: custom discovery property config
  - added: returning distributed and aggregated claims
  - added: Back-Channel Logout draft implementation
  - added: registration.success event
  - added: allow clients for introspections/revocations only (Resource Servers) with no
  authorization flow access
  - added: draft / experimental features now warn upon provider init
  - fix: introspection follows normal/pairwise subject claim of the token's client
  - fix: added client_id_issued_at client property upon registration
- https://github.com/panva/node-oidc-provider/compare/v0.8.1...v0.9.0
  - added: (no)cache headers according to specs
  - fix: consent_required error now returned when consent prompt is not resolved
  - fix: now validates payload of none-signed id_token_hints
  - fix: signed userinfo token expiration
  - fix: unsigned (when id_token_signed_response_alg is not defined, not when none) are now properly
  unsigned, jwe payload is the userinfo response, not a jwt
- https://github.com/panva/node-oidc-provider/compare/v0.7.2...v0.8.1
  - fixed a bug that allowed userinfo and idtoken encrypting clients to pass validation
  - account is configured entirely different now - check examples!
- https://github.com/panva/node-oidc-provider/compare/v0.7.1...v0.7.2
  - fixed a bug that prevented non default client auth strategies to be recognized for introspection
  and revocation
- https://github.com/panva/node-oidc-provider/compare/v0.7.0...v0.7.1
  - fixed a bug that prevented refresh_token grant from issuing an id_token
- https://github.com/panva/node-oidc-provider/compare/v0.6.0...v0.7.0
  - all things `authentication` renamed to `authorization`
- https://github.com/panva/node-oidc-provider/compare/v0.5.0...v0.6.0
- https://github.com/panva/node-oidc-provider/compare/v0.4.0...v0.5.0
- https://github.com/panva/node-oidc-provider/compare/v0.3.1...v0.4.0
- https://github.com/panva/node-oidc-provider/compare/v0.3.0...v0.3.1
- https://github.com/panva/node-oidc-provider/compare/v0.2.0...v0.3.0

### Token Integrity
pre-0.11 all oauth tokens used JWT for serialization and your mandatory RS256 able key for
integrity validation and the string value was > 300 characters long containing the body and signature
part of the JWT with all sensitive information pushed to the header part which only remained in your
storage/adapter.  
Whenever a token would be presented it would be decoded for jti, looked up, and it's signature
validated. This is problematic for providers who want to rotate their signing keys without
invalidating issued tokens. You couldn't choose which key is used for integrity check, you
had no control over the alg used, causing tokens to be issued slowly in high concurrency scenarios.  
0.11 by default comes with token integrity disabled, oauth tokens will not be cryptographically
signed and instead just be random values (which is fine for most).  
To enable the extra layer of protection (essentially against someone controlling your tokens via the
storage layer) you just need to pass a jose.JWK.KeyStore as `tokenIntegrity` configuration option.
The first token you push on to this key store will be used to cryptographically sign the oauth tokens
prohibiting any tampering with the payload and header content.

[debug-link]: https://github.com/visionmedia/debug
