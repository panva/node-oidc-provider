# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

# [6.0.0-alpha.2](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.1...v6.0.0-alpha.2) (2019-04-18)


### Bug Fixes

* device flow - mark codes as already used at the right time ([7b913fd](https://github.com/panva/node-oidc-provider/commit/7b913fd))


### Code Refactoring

* remove provider.initialize() ([ec71ed0](https://github.com/panva/node-oidc-provider/commit/ec71ed0))


### BREAKING CHANGES

* `provider.initialize()` has been removed.
* what was previously passed to `initialize()` as
`keystore` must now be passed as configuration property (as `jwks`) and
it must be a JWKS formatted object, no longer a KeyStore instance.
* what was previously passed to `initialize()` as
`clients` must now be passed as configuration property (as `clients`)
and may not contain `sector_identifier_uri`,
* what was previously passed to `initialize()` as
`adapter` must now be passed as configuration property (as `adapter`).
* provider will no longer call `adapter`'s `connect`
method.



# [6.0.0-alpha.1](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.0...v6.0.0-alpha.1) (2019-04-16)


### Bug Fixes

* _jwt client auth method alg no longer mixes up (a)symmetrical ([1771655](https://github.com/panva/node-oidc-provider/commit/1771655))
* acceptedClaimsFor filtering out claims not scopes ([fd8f886](https://github.com/panva/node-oidc-provider/commit/fd8f886))
* allow all incoming headers for CORS requests ([3d2c8e4](https://github.com/panva/node-oidc-provider/commit/3d2c8e4))
* client key agreement with ECDH-ES is not possible in two cases ([5c39f6e](https://github.com/panva/node-oidc-provider/commit/5c39f6e))
* fail logout when post_logout_redirect_uri is not actionable ([b3a50ac](https://github.com/panva/node-oidc-provider/commit/b3a50ac))
* html-rendered response modes now honour 400 and 500 status codes ([9771581](https://github.com/panva/node-oidc-provider/commit/9771581))
* session required client properties control the iss & sid return ([ab08cbe](https://github.com/panva/node-oidc-provider/commit/ab08cbe))


### Code Refactoring

* remove request/request http client handling and methods ([683e6c2](https://github.com/panva/node-oidc-provider/commit/683e6c2))


### Features

* enable client-based CORS origin whitelisting ([8b4fd9e](https://github.com/panva/node-oidc-provider/commit/8b4fd9e))
* passthrough cors middleware if pre-existing headers are present ([6ec09ef](https://github.com/panva/node-oidc-provider/commit/6ec09ef)), closes [#447](https://github.com/panva/node-oidc-provider/issues/447)
* replay prevention for client assertions is now built in ([a22d6ce](https://github.com/panva/node-oidc-provider/commit/a22d6ce))
* request objects are now one-time use if they have iss, jti and exp ([1dc44dd](https://github.com/panva/node-oidc-provider/commit/1dc44dd))


### BREAKING CHANGES

* Due to request's maintenance mode and inevitable
deprecation (see https://github.com/request/request/issues/3142)
the option to switch the provider to use request has been removed.
* end_session_endpoint will now throw an error when
clients provide post_logout_redirect_uri but fail to provide an
id_token_hint. See https://bitbucket.org/openid/connect/issues/1032



<a name="6.0.0-alpha.0"></a>
# [6.0.0-alpha.0](https://github.com/panva/node-oidc-provider/compare/v5.5.5...v6.0.0-alpha.0) (2019-03-23)

### Features
- it is now possible to issue Refresh Tokens without the offline_access scope, these refresh tokens
  and all access tokens issued from it will be unusable when the session they're tied to gets
  removed or its subject changes
  - Session now has a `uid` property which persists throughout the cookie identifier rotations and
    its value is stored in the related tokens as `sessionUid`, it is based on this value that the
    provider will perform session lookups to ensure that session bound tokens are still considered
    valid
  - by default a session bound grant is one without offline_access, this can be changed, or
    completely disabled to restore previous behaviour with a new `expiresWithSession` helper
- `issueRefreshToken` configuration helper has been added, it allows to define specific client and
  context based policy about whether a refresh token should be issued or not to a client
- `formats.extraJwtAccessTokenClaims` configuration option added, this async function will be called
  whenever a JWT format AccessToken or ClientCredentials is being created
- Updated Device Flow draft implementation - draft 15 now requires the same client authentication
  mechanism to be present at the device_authorization_endpoint
- interactions will now be requested multiple times if the authorization request context cannot be
  resolved yet. This means you can now resolve one prompt at a time. When you load the interaction
  details (using `provider.interactionDetails()`), in addition to `details.params` containing the
  complete parsed authorization parameters object, you now also have access to `details.prompt`
  containing an object with the prompt details.
  - `details.prompt.name` has the name prompt, e.g. `login`
  - `details.prompt.reasons` has an array of reasons the prompt is being requested, e.g. `["max_age"]`
  - `details.prompt.details` contains is an object of details you might need to resolve the prompt
  - `details.session` is an object containing details about the OP session as-is at the moment
    of requesting interaction
    - `details.session.uid` is the internal session's uid
    - `details.session.cookie` is the session cookie value
    - `details.session.acr` is the current session's acr if there's one
    - `details.session.amr` is the current session's amr if there's one
    - `details.session.accountId`
- interactions results `consent.rejectedScopes` and `consent.rejectedClaims` will no longer
  replace the existing values, the rejected scopes and claims will accumulate instead, the same
  happens with what's assumed accepted (that is everything thats been requested and wasn't rejected)
- `end_session_endpoint` now accepts a POST with the parameters being in the body of the request,
  this is so that clients avoid URL length limits and exposing PII in the URL. See
  [OIDC Issues tracker](https://bitbucket.org/openid/connect/issues/1056/use-of-id_token-in-rp-initiated-logout-as)
- Updated OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens draft
  implementation - draft 13
  - client's `certificate_bound_access_tokens`, now also binds the Refresh Token if the client is
    using "none" endpoint auth method
  - SAN based client properties are now recognized, they are not however, supported and will throw
    when presented
- Updated Device Flow draft implementation - draft 15
  - the same client authentication as for token_endpoint is now used at the device_authorization_endpoint
  - once a user code passes the device confirmation prompt it cannot be used again
- `end_session_endpoint` is now always available, it is not bound to any of the session or logout
  specification features
- clients may now have a `scope` property, when set authorization requests for this client
  must stay within those whitelisted scopes
- `end_session_endpoint` will now drop session-bound tokens for the clients/grants encountered
  in the session
- when the existing session's subject (end-user identifier) differs from one inside interaction
  results the provider will bounce the user agent through the end_session_endpoint to perform a
  "clean" logout - drop the session, perform front and back-channel logout notifications (if
  enabled) and revoke grants (if bound to session)
- end session endpoint will now revoke tokens bound to the user-agent session by grantId for the
  clients that have had their authorization removed
- `rotateRefreshToken` configuration added, it can be a function to allow for client and context
  based policy for deciding whether refresh token should rotated or not
- the provider can now process non-openid authorization requests
  - requests without an `openid` scope or `scope` parameter altogether will be processed as plain
    OAuth2.0 authorization requests
  - this has a few exceptions:
    - response types that include id_token still require the `openid` scope
    - use of openid feature related parameters such as `claims`, `acr_values`, `id_token_hint` and
      `max_age` still require the `openid` scope
    - use of openid feature related client attributes such as `default_acr_values`,
      `default_max_age`, `require_auth_time` still require the `openid` scope
  - use of the `userinfo_endpoint` is only possible with access tokens that have the `openid` scope
  - note: the scope claim in JWT access tokens will be missing if the parameter was missing as well,
    dtto for the scope property in your persitent storage
- authorization parameter `max_age=0` now behaves like `prompt=login` (dtto client's
  `default_max_age=0`)
- every model now has its own `saved` and `destroyed` event emitted by the provider, sessions and
  interactions too, the convention is `{snake_cased_model_name}.{saved|destroyed}`
- `urn:` request_uri support added, provided that one overloads
  `provider.Client.prototype.requestUriAllowed` and `provider.requestUriCache.resolveUrn`
- `http:` request_uris are now allowed under the assumption that the request object it yields is
  verifiable (signed and/or symmetrically encrypted)
- added `invalid_software_statement` and `unapproved_software_statement` exported errors


### Bug Fixes

- subsequent authorization requests for the same combination of client, end-user and sessionUid will
  all have the same `grantId` value now
- `PKCE` is no longer forced for `grant_type=urn:ietf:params:oauth:grant-type:device_code`
- response_type `code token` no longer requires nonce parameter to be present. See
  [OIDC Core 1.0 Errata 2 changeset](https://bitbucket.org/openid/connect/commits/31240ed1f177b16b589b54c3795ea0187fa5b85e)
- provider no longer reject client registration when the `jwks.keys` is empty
- provider now rejects client's `jwks` and `jwks_uri` if they contain private key material. See
  [OIDC Core 1.0 Errata 2 changeset](https://bitbucket.org/openid/connect/commits/f91efe0f583d9e8a96a7717f454e1822041feb14)
- Client will no longer be looked up twice during failed authorization due to client not being found
- `max_age` parameter is now validated to be a non-negative safe integer
- PBES2 symmetric encryption now correctly uses the `client_secret` value rather then its SHA digest
- client secrets no longer need to have minimal length to support HS signing
- established session acr/amr is now available for any authorization request, not just the one it
  was established with

### BREAKING CHANGES
- Node.js version >= 11.8.0 is now required, it is expected oidc-provider v6.0.0 will release after
  node v12.0.0 and that will be the required version
- all exported JWK related methods have been removed
- JWT Access Token can now only be signed using the provider's asymmetric keys, client's HS will no
  longer be used
- `sid` ID Token claim is now only returned when the client requests it using the `claims` parameter
  or has the appropriate back/front channel logout uris enabled and front/backchannel_logout_session_required
  set to true
- the provider now uses `@panva/jose` module instead `node-jose`, this module brings in improvements
  in JWS/JWE performance due to its use of `KeyObject` API introduced in Node.js v11.6.0
- clients with `request_object_signing_alg` set must now always provide a request object,
  authorization requests will fail with `invalid_request` when `request` or `request_uri` is missing
  for such clients
- adapter changes to accomodate new functionality
  - it is no longer desired to drop all related tokens when `#destroy` is called
  - Session adapter instance expects to have a `findByUid` method which resolves with the same data
    as `find` does only the reference is the session's `uid` property. This is only needed when
    utilizing the new session-bound tokens
  - AccessToken, RefreshToken, AuthorizationCode & DeviceCode adapter instances expect to have
    `revokeByGrantId` method which accepts a string parameter `grantId` and revokes all tokens
    with its matching value in the `grantId` property
- only `AccessToken` and `ClientCredentials` may have a format. All other tokens are now forced to
  be opaque
- `clientCacheDuration` configuration option and `provider.Client.cacheClear` method have been
  removed, the provider now handles everything internally and Client objects are re-instantiated
  automatically if the client's configuration changes.
- `token.*` events are no longer emitted, instead each token has its own event, sessions and
  interactions too, the convention is `snake_cased_model_name.*`
- `features.pkce` and `features.oauthNativeApps` are now not configurable and always in effect, pkce
  is always forced on native clients
- `iss` is no longer pushed to token/model storage payloads
- `features.sessionManagement.thirdPartyCheckUrl` has been removed
- `features.alwaysIssueRefresh` has been removed
- `features.refreshTokenRotation` has been renamed to `features.rotateRefreshToken` and its values
  are now true/false or a function that returns true/false when a refresh token should or should not
  be rotated
- `features.conformIdTokenClaims` is not a feature anymore, it is just `conformIdTokenClaims` in the
  configuration object's root
- revoking an Access Token via the `revocation_endpoint` will not revoke the whole grant any more
- default `interaction` cookie name value changed from `_grant` to `_interaction`
- default `resume` cookie name value changed from `_grant` to `_interaction_resume`
- all references to `ctx.oidc.uuid` are now `ctx.oidc.uid` and the format is now a random string,
  not a uuid
- nearly all emitted events have had their arguments shuffled and/or changed to allow for `ctx` to
  be first
- nearly all helper functions have had their arguments shuffled and/or changed to allow for `ctx` to
  be the first amongst them (oh yeah, `ctx` has been added almost everywhere)
- all configuration `features` are no longer booleans, they're objects with all their relevant
  configuration in the `defaults.js` file and `docs/README.md`. Old configuration format is not
  accepted anymore
- some configuration properties that only relate to a specific features were moved from the root
  level to the feature's configuration level and have been renamed, these are
  - `deviceFlowSuccess` -> `features.deviceFlow.successSource`
  - `frontchannelLogoutPendingSource` -> `features.frontchannelLogout.logoutPendingSource`
  - `userCodeConfirmSource` -> `features.deviceFlow.userCodeConfirmSource`
  - `userCodeInputSource` -> `features.deviceFlow.userCodeInputSource`
- Session model has been split to Session and Interaction
- interaction login result now defaults to `remember: true`
- `legacy` storage format has been removed
- adding additional audiences through the `audiences` helper to signed userinfo or ID Tokens has
  been removed (it remains for the rest of the use cases)
- the `.well-known/webfinger` endpoint that always returned success is removed
- default `deviceFlow.deviceInfo` `userAgent` property is now `ua`

### Other changes / deprecations

- example mongo and redis adapters revised
- example redis with ReJSON module adapter added
- example unmaintained adapters removed


<a name="5.5.5"></a>
## [5.5.5](https://github.com/panva/node-oidc-provider/compare/v5.5.4...v5.5.5) (2019-02-20)


### Bug Fixes

* expose only supported cors methods ([4a81104](https://github.com/panva/node-oidc-provider/commit/4a81104))
* replace router again to fix CORS preflights ([d642f8b](https://github.com/panva/node-oidc-provider/commit/d642f8b))



<a name="5.5.4"></a>
## [5.5.4](https://github.com/panva/node-oidc-provider/compare/v5.5.3...v5.5.4) (2019-02-15)


### Refactored

* removed koa-router in favor of koa-trie-router ([fe812e0](https://github.com/panva/node-oidc-provider/commit/fe812e0)), closes [#436](https://github.com/panva/node-oidc-provider/issues/436)


<a name="5.5.3"></a>
## [5.5.3](https://github.com/panva/node-oidc-provider/compare/v5.5.2...v5.5.3) (2019-01-22)


### Bug Fixes

* handle server_error when refresh tokens are missing `gty` ([75046ca](https://github.com/panva/node-oidc-provider/commit/75046ca))



<a name="5.5.2"></a>
## [5.5.2](https://github.com/panva/node-oidc-provider/compare/v5.5.1...v5.5.2) (2018-12-20)


### Bug Fixes

* JWKStore prototype jwksUri undefined client ([#413](https://github.com/panva/node-oidc-provider/issues/413)) ([ba69fb6](https://github.com/panva/node-oidc-provider/commit/ba69fb6))



<a name="5.5.1"></a>
## [5.5.1](https://github.com/panva/node-oidc-provider/compare/v5.5.0...v5.5.1) (2018-11-26)


### Bug Fixes

* added aud and azp validations for ID Tokens passed by clients ([4df8160](https://github.com/panva/node-oidc-provider/commit/4df8160))
* aud for jwt oauth tokens no longer gets the client id pushed in ([14c556e](https://github.com/panva/node-oidc-provider/commit/14c556e))



<a name="5.5.0"></a>
# [5.5.0](https://github.com/panva/node-oidc-provider/compare/v5.4.2...v5.5.0) (2018-11-22)


### Bug Fixes

* gracefully handle mixed up response_type(s) order ([b775591](https://github.com/panva/node-oidc-provider/commit/b775591))
* http2 is also stable in ^8.13.0 ([3d240d9](https://github.com/panva/node-oidc-provider/commit/3d240d9))


### Features

* initial and registration access token policies ([452000c](https://github.com/panva/node-oidc-provider/commit/452000c)), closes [#394](https://github.com/panva/node-oidc-provider/issues/394)



<a name="5.4.2"></a>
## [5.4.2](https://github.com/panva/node-oidc-provider/compare/v5.4.1...v5.4.2) (2018-11-19)


### Bug Fixes

* ignore `*_endpoint_auth_signing_alg` client metadata when `_jwt` auth is not allowed ([d0346a8](https://github.com/panva/node-oidc-provider/commit/d0346a8))



<a name="5.4.1"></a>
## [5.4.1](https://github.com/panva/node-oidc-provider/compare/v5.4.0...v5.4.1) (2018-11-19)


### Bug Fixes

* require consent result to save accepted scopes and claims ([7720367](https://github.com/panva/node-oidc-provider/commit/7720367))



<a name="5.4.0"></a>
# [5.4.0](https://github.com/panva/node-oidc-provider/compare/v5.3.0...v5.4.0) (2018-11-18)


### Bug Fixes

* handle potentially unvalidated response mode in authz error handler ([ee501d1](https://github.com/panva/node-oidc-provider/commit/ee501d1))
* issue new session identifiers when session changes ([56d04e6](https://github.com/panva/node-oidc-provider/commit/56d04e6))
* omit saving an empty session on initial authorize request ([d0b7069](https://github.com/panva/node-oidc-provider/commit/d0b7069))


### Features

* allow omitting redirect_uri in code exchange at the token endpoint when there is just one registered ([8cdd407](https://github.com/panva/node-oidc-provider/commit/8cdd407))
* update of draft-ietf-oauth-resource-indicators from 00 to 01 ([1302a54](https://github.com/panva/node-oidc-provider/commit/1302a54)), closes [#385](https://github.com/panva/node-oidc-provider/issues/385)



<a name="5.3.0"></a>
# [5.3.0](https://github.com/panva/node-oidc-provider/compare/v5.2.0...v5.3.0) (2018-11-05)


### Bug Fixes

* upgrade min node-jose version to fix its performance in node ([f1cb4c6](https://github.com/panva/node-oidc-provider/commit/f1cb4c6))


### Features

* sessionManagement frame uses Storage Access API to detect errors ([156e12d](https://github.com/panva/node-oidc-provider/commit/156e12d))



<a name="5.2.0"></a>
# [5.2.0](https://github.com/panva/node-oidc-provider/compare/v5.1.2...v5.2.0) (2018-11-01)


### Draft Features

* sessionManagement feature doesn't set a default thirdPartyCheckUrl anymore ([0015c38](https://github.com/panva/node-oidc-provider/commit/0015c38))

With the sunset of https://rawgit.com i'm not going to look for a replacement CDN that hosts github
content using the right content-type. This addition to sessionManagement is a gimmick helping only
in a small % of cases anyway.

Note: Updates to draft and experimental specification versions are released as MINOR library versions,
if you utilize these specification implementations consider using the tilde `~` operator in your
package.json since breaking changes such as this one may be introduced as part of these version updates.



<a name="5.1.2"></a>
## [5.1.2](https://github.com/panva/node-oidc-provider/compare/v5.1.0...v5.1.2) (2018-10-23)


### Bug Fixes

* allow http2 req/res in interaction detail helpers (fixes [#383](https://github.com/panva/node-oidc-provider/issues/383)) ([a86aba7](https://github.com/panva/node-oidc-provider/commit/a86aba7))



<a name="5.1.0"></a>
# [5.1.0](https://github.com/panva/node-oidc-provider/compare/v5.0.1...v5.1.0) (2018-10-03)


### Bug Fixes

* ignore sector_identifier_uri when subject_type is not pairwise ([416e379](https://github.com/panva/node-oidc-provider/commit/416e379))


### Features

* add Resource Indicators for OAuth 2.0 - draft 00 implementation ([1bc2994](https://github.com/panva/node-oidc-provider/commit/1bc2994))



<a name="5.0.1"></a>
## [5.0.1](https://github.com/panva/node-oidc-provider/compare/v5.0.0...v5.0.1) (2018-09-27)



<a name="5.0.0"></a>
# [5.0.0](https://github.com/panva/node-oidc-provider/compare/v4.8.3...v5.0.0) (2018-09-26)


### Bug Fixes

* change conformIdTokenClaims default value to true ([ef40f6d](https://github.com/panva/node-oidc-provider/commit/ef40f6d))
* devInteractions also have no-cache headers, doesn't set acr ([9d7a032](https://github.com/panva/node-oidc-provider/commit/9d7a032))
* ensure non-whitelisted JWA algs cannot be used by `*_jwt` client auth ([186de0d](https://github.com/panva/node-oidc-provider/commit/186de0d))
* extraClientMetadata.properties keys do not get transformed ([837beca](https://github.com/panva/node-oidc-provider/commit/837beca))
* fixed 500 in client update checking client_secret equality ([bad6348](https://github.com/panva/node-oidc-provider/commit/bad6348))
* remove deprecated passing of scope with consent results ([35f13bc](https://github.com/panva/node-oidc-provider/commit/35f13bc))
* remove deprecated Session.find upsert behaviour ([73e07bd](https://github.com/panva/node-oidc-provider/commit/73e07bd))
* remove deprecated unused exported errors ([fc3f509](https://github.com/panva/node-oidc-provider/commit/fc3f509))
* remove got 8 > 9(retries > retry) option re-assign behaviour ([db31d32](https://github.com/panva/node-oidc-provider/commit/db31d32))
* secretFactory is now used in client update ([0923f52](https://github.com/panva/node-oidc-provider/commit/0923f52))
* validate secret length for client_secret_jwt with no alg specified ([ab64268](https://github.com/panva/node-oidc-provider/commit/ab64268))


### Code Refactoring

* IdToken constructor and `#sign()` method changes ([bb4269f](https://github.com/panva/node-oidc-provider/commit/bb4269f))
* moved thirdPartyCheckUrl under features.sessionManagement ([c3f84b2](https://github.com/panva/node-oidc-provider/commit/c3f84b2))
* renamed deviceCode feature to deviceFlow ([cd57d77](https://github.com/panva/node-oidc-provider/commit/cd57d77))


### Features

* add self_signed_tls_client_auth client authentication method ([9a1f0a3](https://github.com/panva/node-oidc-provider/commit/9a1f0a3))
* add tls_client_auth client authentication method ([ce2bf66](https://github.com/panva/node-oidc-provider/commit/ce2bf66))
* allow custom mechanisms for handling pairwise identifiers ([57ce6d7](https://github.com/panva/node-oidc-provider/commit/57ce6d7))
* back and front-channel can be enabled without sessionManagement ([8cb37ff](https://github.com/panva/node-oidc-provider/commit/8cb37ff))
* dynamic token expiration ([6788b83](https://github.com/panva/node-oidc-provider/commit/6788b83))
* enable Certificate Bound Access Tokens ([f43d820](https://github.com/panva/node-oidc-provider/commit/f43d820))
* enable explicit whitelist of JWA algorithms ([0604e08](https://github.com/panva/node-oidc-provider/commit/0604e08))
* enable token storage and representation format to be dynamic ([8487bd8](https://github.com/panva/node-oidc-provider/commit/8487bd8))
* invalid_token errors now have a detail to aid in debugging or logs ([b8324b7](https://github.com/panva/node-oidc-provider/commit/b8324b7))
* JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) ([c759415](https://github.com/panva/node-oidc-provider/commit/c759415))
* opaque is the default adapter format now ([75e7a3f](https://github.com/panva/node-oidc-provider/commit/75e7a3f))
* unify audiences helper function signature ([fd38600](https://github.com/panva/node-oidc-provider/commit/fd38600))


### BREAKING CHANGES

* the configuration option `pairwiseSalt` is replaced
with `pairwiseIdentifier` async helper function. This allows for
different means of generating the pairwise identifier to be implemented,
such as the ones mentioned in [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.8.1)
* Passing `scope` to interaction result's `consent`
property is no longer supported
* `cookies.thirdPartyCheckUrl` is now configured
with `features.sessionManagement.thirdPartyCheckUrl` instead
* `features.deviceCode` is now `features.deviceFlow` and `deviceCodeSuccess` helper function is now
`deviceFlowSuccess`
* In order for dynamic token expiration to be able to
pass a client instance to the helpers it is now better to pass a
`client` property being the client instance to a new token instance
rather then a `clientId`. When passing a client the `clientId` will be
set automatically.
* the default adapter format is now set to opaque,
the legacy "legacy" value is still available for legacy deployments but
cannot be combined with the new dynamic format feature option and is
considered deprecated and will be removed in the next major release.
* the `default` enabled JWA algorithms have changed. See
the new `whitelistedJWA` configuration option to re-enable the ones you
need.
* the configuration `unsupported` property is removed,
use the configuration `whitelistedJWA` object instead. This isn't a 1:1
renaming of a configuration value, while the `unsupported` option was
essentually a blacklist the `whitelistedJWA` as the name suggests is a
whitelist.
* the `RSA-OAEP-256` key wrapping algorithm has been
removed and is not configurable since it is not supported natively in
nodejs.
* IdToken constructor now requires the client instance
to be passed in as a second argument. IdToken instance `.sign()` now
takes just one argument with the options.
* when a symmetrical endpoint authentication signing alg
is not specified the secret will be validated such that it can be used
with all available HS bit lengths
* audience helper `token` argument will no longer be
a reference to other tokens than the one to which the audiences will be
pushed.
* audience helper `scope` argument is no longer available
* `generateTokenId` format method is now a prototype method instead of a class one
* the http request option `retries` will no longer
be transformed into `retry`, see `got@^9.0.0` package for the `retry`
options
* exported errors `RestrictedGrantType` and
`RestrictedResponseType` are no longer available
* Session.find default upsert behaviour is changed to
return a new empty session instead
* change conformIdTokenClaims default value to true
* custom client metadata properties will not get
transformed between snake_case and camelCase anymore to allow for
namespaced metadata properties such as `custom://metadata`



<a name="4.8.3"></a>
## [4.8.3](https://github.com/panva/node-oidc-provider/compare/v4.8.2...v4.8.3) (2018-09-20)


### Bug Fixes

* reference correct param names in `features.webMessageResponseMode` ([e495c6b](https://github.com/panva/node-oidc-provider/commit/e495c6b))



<a name="4.8.2"></a>
## [4.8.2](https://github.com/panva/node-oidc-provider/compare/v4.8.1...v4.8.2) (2018-09-16)


### Bug Fixes

* do not overwrite custom response mode implementations with defaults ([7f7ea79](https://github.com/panva/node-oidc-provider/commit/7f7ea79)), closes [#365](https://github.com/panva/node-oidc-provider/issues/365)
* remove unnecessary catchall in fallback session save ([3bfb8f0](https://github.com/panva/node-oidc-provider/commit/3bfb8f0)), closes [#363](https://github.com/panva/node-oidc-provider/issues/363)



<a name="4.8.1"></a>
## [4.8.1](https://github.com/panva/node-oidc-provider/compare/v4.8.0...v4.8.1) (2018-09-06)


### Bug Fixes

* claim definition also detects dynamic scopes ([d8c8170](https://github.com/panva/node-oidc-provider/commit/d8c8170))
* custom registered grants do not get overriden by defaults ([d4185f9](https://github.com/panva/node-oidc-provider/commit/d4185f9)), closes [#349](https://github.com/panva/node-oidc-provider/issues/349)



<a name="4.8.0"></a>
# [4.8.0](https://github.com/panva/node-oidc-provider/compare/v4.7.1...v4.8.0) (2018-08-29)


### Features

* add dynamic scope value support ([caa8f0e](https://github.com/panva/node-oidc-provider/commit/caa8f0e))



<a name="4.7.1"></a>
## [4.7.1](https://github.com/panva/node-oidc-provider/compare/v4.7.0...v4.7.1) (2018-08-27)


### Bug Fixes

* check_session regression fix ([32975d9](https://github.com/panva/node-oidc-provider/commit/32975d9))



<a name="4.7.0"></a>
# [4.7.0](https://github.com/panva/node-oidc-provider/compare/v4.6.0...v4.7.0) (2018-08-26)


### Bug Fixes

* conform claims param parsing ([c553a92](https://github.com/panva/node-oidc-provider/commit/c553a92))
* set session params as undefined instead of delete ([a872091](https://github.com/panva/node-oidc-provider/commit/a872091))


### Features

* accepted scope and rejected claim tracking ([b4c2655](https://github.com/panva/node-oidc-provider/commit/b4c2655))
* session_state changes ([f64d040](https://github.com/panva/node-oidc-provider/commit/f64d040))



<a name="4.6.0"></a>
# [4.6.0](https://github.com/panva/node-oidc-provider/compare/v4.5.0...v4.6.0) (2018-08-13)


### Features

* add client meta to setProviderSession ([1174c76](https://github.com/panva/node-oidc-provider/commit/1174c76)), closes [#352](https://github.com/panva/node-oidc-provider/issues/352)
* check session client Origin check ([6c27f10](https://github.com/panva/node-oidc-provider/commit/6c27f10))
* option to set interactionResult without redirecting to resume right away ([6aeedf2](https://github.com/panva/node-oidc-provider/commit/6aeedf2)), closes [#350](https://github.com/panva/node-oidc-provider/issues/350)
* session management client helper is now inline with other helpers ([96802df](https://github.com/panva/node-oidc-provider/commit/96802df))
* update JWT Response for OAuth Token Introspection draft ([039ab90](https://github.com/panva/node-oidc-provider/commit/039ab90))



<a name="4.5.0"></a>
# [4.5.0](https://github.com/panva/node-oidc-provider/compare/v4.4.0...v4.5.0) (2018-08-03)


### Bug Fixes

* message displayed on blank /device ([86541df](https://github.com/panva/node-oidc-provider/commit/86541df))


### Features

* update device flow to draft-12 ([e00fa52](https://github.com/panva/node-oidc-provider/commit/e00fa52))



<a name="4.4.0"></a>
# [4.4.0](https://github.com/panva/node-oidc-provider/compare/v4.3.2...v4.4.0) (2018-07-22)


### Features

* JWT Response for OAuth Token Introspection ([72142fd](https://github.com/panva/node-oidc-provider/commit/72142fd))



<a name="4.3.2"></a>
## [4.3.2](https://github.com/panva/node-oidc-provider/compare/v4.3.1...v4.3.2) (2018-07-21)


### Bug Fixes

* add a clear error description when sector uri isn't a valid json ([05c14d1](https://github.com/panva/node-oidc-provider/commit/05c14d1))
* allow clients that do not use authorization to utilize pairwise ([c24ea70](https://github.com/panva/node-oidc-provider/commit/c24ea70))



<a name="4.3.1"></a>
## [4.3.1](https://github.com/panva/node-oidc-provider/compare/v4.3.0...v4.3.1) (2018-07-17)


### Bug Fixes

* device_authorization  w/ offline_access scope ([19a85ac](https://github.com/panva/node-oidc-provider/commit/19a85ac))



<a name="4.3.0"></a>
# [4.3.0](https://github.com/panva/node-oidc-provider/compare/v4.2.2...v4.3.0) (2018-07-16)


### Bug Fixes

* allow for pkce to be disabled ([3aca2c8](https://github.com/panva/node-oidc-provider/commit/3aca2c8))
* debug revocation after yield ([bf4c012](https://github.com/panva/node-oidc-provider/commit/bf4c012))
* pathFor returns a valid route for issuers with terminating "/" ([9e4b1a0](https://github.com/panva/node-oidc-provider/commit/9e4b1a0)), closes [#315](https://github.com/panva/node-oidc-provider/issues/315)


### Features

* add Device Flow experimental/draft feature ([461a8e3](https://github.com/panva/node-oidc-provider/commit/461a8e3))
* add gty storage claim for access and refresh token ([a492a5e](https://github.com/panva/node-oidc-provider/commit/a492a5e))
* change the requests's uuid to a previous value of grantId ([28673e2](https://github.com/panva/node-oidc-provider/commit/28673e2))



# Pre standard-version Change Log
## 4.2.x
### 4.2.2
- 2018-07-13 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.2.1...v4.2.2)
- fixed `expiresIn` sent to adapter#upsert when interaction session are saved using interactionFinished()

### 4.2.1
- 2018-07-13 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.2.0...v4.2.1)
- fixed form_post regression for response types including `token` from 4.2.0

### 4.2.0
- 2018-07-12 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.1.3...v4.2.0)

**New Feature - OAuth 2.0 Web Message Response Mode**

Based on [OAuth 2.0 Web Message Response Mode](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00)
response_mode=web_message is a new response mode that uses HTML5 Web Messaging instead of a redirect
for the Authorization Response from the Authorization Endpoint. It defines two modes: simple mode
and relay mode. Relay mode can be used to protect the response by confining it within the origins of
a resource server and preventing it from being read by the client.

This is released as an experimental/draft feature so as with the others it is disabled by default and
breaking changes to this feature will be released as MINOR releases. When using Web Message Response
Mode be sure to lock down `oidc-provider` in your package.json with the tilde `~` operator and pay
close attention to this changelog when updates are released.

To enable configure:
```js
const configuration = { features: { webMessageResponseMode: true } };
```
Note: Although a general advise to use a `helmet`([express](https://www.npmjs.com/package/helmet),
[koa](https://www.npmjs.com/package/koa-helmet)) it is especially advised for your interaction views
routes if Web Message Response Mode is available on your deployment.

**Enhancements**
- added no-cache headers to the authorization endpoint
- `#provider.setProviderSession()` now returns the created session object
- `#provider.registerGrantType()` also accepts additional parameter to indicate parameters for which
  duplicates are allowed (e.g. `audience` and `resource` in OAuth 2.0 Token Exchange)

**Fixes**
- fixed some edge cases where authorization error responses would still reach the redirect_uri even
  when it could not have been validated
- fixed parameters coming from Request Objects to be always used as strings
- fixed upstream body parser params to be always strings (unless json)
- fixed parameters coming multiple times still being used in error handlers (e.g. state)
- fixed form post values not being html escaped

## 4.1.x
### 4.1.3
- 2018-06-28 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.1.2...v4.1.3)
- fixed `www-authenticate` header uses in bearer token endpoints according to Core 1.0 and RFC6750

### 4.1.2
- 2018-06-26 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.1.1...v4.1.2)
- fixed missing `sid` claim in access tokens
- fixed non-consumable tokens having `consumed` stored and `#consume()` instance method

### 4.1.1
- 2018-06-25 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.1.0...v4.1.1)
- fixed missing `sub` claim from tokens when using the `jwt` format
- chores (lint, tests, refactors, default error and logout screen styles)

### 4.1.0
- 2018-06-22 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.0.3...v4.1.0)

**New Feature - Storage Formats**

Added `formats` configuration option. This option allows to configure the token storage and value
formats. The different values change how a token value is generated as well as what properties get
sent to the adapter for storage. Three formats are defined:

- `legacy` is the current and default format until next major release. no changes in the format sent
  to adapter
- `opaque` formatted tokens have a different value then `legacy` and in addition store what was in
  legacy format encoded under `payload` as root properties, this makes analysing the data in your
  storage way easier
- `jwt` formatted tokens are issued as JWTs and stored the same as `opaque` only with additional
  property `jwt`. The signing algorithm for these tokens uses the client's
  `id_token_signed_response_alg` value and falls back to `RS256` for tokens with no relation to a
  client or when the client's alg is `none`

This feature uses the previously defined public token API of `[klass].prototype.getValueAndPayload,
[klass].prototype.constructor.getTokenId, [klass].prototype.constructor.verify` and adds a new one
`[klass].prototype.constructor.generateTokenId`. See the inline comment docs for more detail on those.
Further format ideas and suggestions are welcome.


**New Feature - `conformIdTokenClaims` feature toggle**
Added `conformIdTokenClaims` feature toggle.

This toggle makes the OP only include End-User claims in the ID Token as defined by Core 1.0 section
5.4 - when the response_type is id_token or unless requested using the claims parameter.


**Fixes**
- fixed edge cases where client and provider signing keys would be used for encryption and vice versa
- fixed client `request_object_signing_alg` and `contact` validations
- fixed `defaultHttpOptions` to be as documented
- fixed an end_session server error in case where session.authorizations is missing - #295
- adjusted error_description to be more descriptive when PKCE plain value fallback is not possible
  due to the plain method not being supported
- fixed `audiences` helper results to assert that an array of strings is returned
- fixed issues with interaction sessions and the back button, assertions are now in place and both
  resume endpoint and interaction helpers will now reject with SessionNotFound named error, which
  is essentially just InvalidRequest with a more descriptive name.


## 4.0.x
### 4.0.3
- 2018-06-09 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.0.2...v4.0.3)
- fixed token endpoint `grant_type=refresh_token` scope parameter related bugs
  - a rotated refresh token will retain the original scope, its only the access and id token that
    has the requested scope as specified in section 6 of RFC6749
  - `openid` scope must be provided in the list of requested scopes

### 4.0.2
- 2018-06-05 [DIFF](https://github.com/panva/node-oidc-provider/compare/v4.0.1...v4.0.2)
- fixed non-spec errors `restricted_response_type` and `restricted_grant_type` to be UnauthorizedClient
  (`unauthorized_client`) instead as specified in RFC6749
- fixed missing `WWW-Authenticate` response header in Bearer auth scheme endpoints when 401 is
  returned (was missing from `registration_endpoint`, `registration_client_uri`)
- fixed `#session.save()` when `cookies.*.maxAge` is set to `0` to not add the `exp` claim - #289
- fixed the `remember=false` option to apply to client session state cookies too

### 4.0.1
- 2018-06-01 [DIFF](https://github.com/panva/node-oidc-provider/compare/v3.0.3...v4.0.1)

**Breaking changes**
- minimal version of node lts/carbon is required (>=8.9.0)
- **Client Metadata** - null property values are no longer ignored
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
      if (err instanceof Provider.errors.InvalidClientAuth) {
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
- all error classes the provider emits/throws are now exported in `Provider.errors[class]` instead of
  `Provider[class]` and the class names are no longer suffixed by `Error`. See `console.log(Provider.errors)`
- removed the non-spec `rt_hash` ID Token claim
- `features.pkce` now only enables `S256` by default, this is sufficient for most deployments. If
  `plain` is needed enable pkce with `{ features: { pkce: { supportedMethods: ['plain', 'S256'] } }`.
- `client.backchannelLogout` no longer suppresses any errors, instead rejects the promise
- token introspection endpoint no longer returns the wrong `token_type` claim - #189
  - to continue the support of this non-standardized claim from introspection you may register the following middleware
    ```js
    provider.use(async function introspectionTokenType(ctx, next) {
      await next();
      if (ctx.oidc.route === 'introspection') {
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
- default configuration values for `cookies.short.maxAge` and `cookies.long.maxAge` changed
- `audiences` is now in addition to existing `id_token` and signed `userinfo`
  cases called for `client_credentials` and `access_token`, this is useful for pushing additional audiences
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
  - removed deprecated `#provider.setSessionAccountId()` helper method. Use `#provider.setProviderSession()`
    instead

**Enhancements**
- **Session Changes**
  - stored sessions now have an `exp` property allowing the provider to ignore expired but
    still returned sessions
    - existing sessions without this property will be accepted and the exp property will be added
      with the next save
- bumped the semantic version of every dependency to the latest as of release
- added `aud` to the introspection response if a token has one
- `audiences` helper gets called with additional parameters `use` and `scope`
- `renderError` helper is now called with a third argument that's the actual Error instance.
- `node-jose` dependency bumped to major ^1.0.0 - fixes `A\d{3}GCMKW` symmetrical encryption support
- added `cookies.thirdPartyCheckUrl` option and a warning to host it
- moved middleware handling missing optionally `redirect_uri` parameter case right after loading
  the client

## 3.0.x
### 3.0.3
- 2018-05-23 [DIFF](https://github.com/panva/node-oidc-provider/compare/v3.0.2...v3.0.3)
- all options passed to defaultHttpOptions now also reach `request` when `#useRequest()` is used
- fixed a case when RS256 key presence check was wrongly omitted during `#initialize()`
- fixed client `jwks_uri` refresh error to be invalid_client_metadata and propagated to the client

### 3.0.2
- 2018-05-15 [DIFF](https://github.com/panva/node-oidc-provider/compare/v3.0.1...v3.0.2)
- base64url dependency replaced

### 3.0.1
- 2018-05-10 [DIFF](https://github.com/panva/node-oidc-provider/compare/v3.0.0...v3.0.1)
- dependency tree updates

### 3.0.0
- 2018-05-02 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.18.0...v3.0.0)
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
- 2018-04-12 [DIFF](https://github.com/panva/node-oidc-provider/compare/v2.17.0...v2.18.0)
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
