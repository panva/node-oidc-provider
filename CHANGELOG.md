# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

# [6.0.0-alpha.8](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.7...v6.0.0-alpha.8) (2019-06-06)


### Bug Fixes

* base accepted scope off the accepted scopes, not param scopes ([ccec5d3](https://github.com/panva/node-oidc-provider/commit/ccec5d3))
* do not send empty error_descriptions with some responses ([663fadc](https://github.com/panva/node-oidc-provider/commit/663fadc))
* enable debugging session bound tokens not being returned ([cc66876](https://github.com/panva/node-oidc-provider/commit/cc66876))


### Features

* default refresh token rotation policy changed ([7310765](https://github.com/panva/node-oidc-provider/commit/7310765))


### BREAKING CHANGES

* default `rotateRefreshToken` configuration value
is now a function with a described policy that follows
[OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-12)



# [6.0.0-alpha.7](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.6...v6.0.0-alpha.7) (2019-05-29)


### Bug Fixes

* add scope to implicit responses when different from request ([71b2e7e](https://github.com/panva/node-oidc-provider/commit/71b2e7e))
* expose correct discovery metadata jwt introspection signing algs ([cf4e442](https://github.com/panva/node-oidc-provider/commit/cf4e442)), closes [#475](https://github.com/panva/node-oidc-provider/issues/475)
* hide disabled features from discovery ([967c829](https://github.com/panva/node-oidc-provider/commit/967c829))
* jwt client assertion audience now also accepts issuer and token url ([38706e7](https://github.com/panva/node-oidc-provider/commit/38706e7))
* use fixed scope to claim mapping over dynamic ones ([03a6130](https://github.com/panva/node-oidc-provider/commit/03a6130)), closes [#466](https://github.com/panva/node-oidc-provider/issues/466)



# [6.0.0-alpha.6](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.5...v6.0.0-alpha.6) (2019-05-21)


### Bug Fixes

* check sameSite cookie option for none case-insensitive ([523d1b2](https://github.com/panva/node-oidc-provider/commit/523d1b2))
* handle client jwks x5c when kty is OKP, use client jwks key_ops ([f052f6b](https://github.com/panva/node-oidc-provider/commit/f052f6b))


### Features

* add per-request http options helper function configuration ([4aee414](https://github.com/panva/node-oidc-provider/commit/4aee414))
* discovery must now always be enabled ([5c3c0c7](https://github.com/panva/node-oidc-provider/commit/5c3c0c7))


### BREAKING CHANGES

* removed features.discovery and it is now always-on, no
point in disabling discovery, ever.
* logoutPendingSource no longer receives a `timeout`
argument
* `provider.defaultHttpOptions` setter was removed, use
the new `httpOptions` configuration helper function instead
* provider now asserts that client's
`backchannel_logout_uri` returns a 200 OK response as per specification.



# [6.0.0-alpha.5](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.4...v6.0.0-alpha.5) (2019-05-17)


### Bug Fixes

* check id_token_hint even if the interaction check is disabled ([7528220](https://github.com/panva/node-oidc-provider/commit/7528220))
* check PKCE verifier and challenge ABNF, remove it from device flow ([849b964](https://github.com/panva/node-oidc-provider/commit/849b964))
* enable Secure cookies with the default settings if on secure req ([a056bfd](https://github.com/panva/node-oidc-provider/commit/a056bfd))
* short cookie options dont affect the resume cookie path scope ([4c7e877](https://github.com/panva/node-oidc-provider/commit/4c7e877))


### Code Refactoring

* rename idToken.sign to idToken.issue ([1c6d556](https://github.com/panva/node-oidc-provider/commit/1c6d556))


### Features

* allow for client default metadata to be changed ([8f20a69](https://github.com/panva/node-oidc-provider/commit/8f20a69))
* allow non-conform instances ([f772f97](https://github.com/panva/node-oidc-provider/commit/f772f97))
* set default sameSite cookie values, short: lax, long: none ([cfb1a70](https://github.com/panva/node-oidc-provider/commit/cfb1a70))


### BREAKING CHANGES

* provider.IdToken.prototype.sign is renamed to
provider.IdToken.prototype.issue
* PKCE code_challenge and code_verifier is now checked
to be 43-128 characters long and conforms to the allowed character set
of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~". PKCE is now also
ignored for the Device Code authorization request and token exchange.



# [6.0.0-alpha.4](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.3...v6.0.0-alpha.4) (2019-05-09)


### Bug Fixes

* rendered OP views are no longer dead ends with javascript disabled ([c2f17d7](https://github.com/panva/node-oidc-provider/commit/c2f17d7))


### Code Refactoring

* rename findById to findAccount to follow the helper convention ([43f5ecc](https://github.com/panva/node-oidc-provider/commit/43f5ecc))


### BREAKING CHANGES

* findById helper was renamed to findAccount



# [6.0.0-alpha.3](https://github.com/panva/node-oidc-provider/compare/v6.0.0-alpha.2...v6.0.0-alpha.3) (2019-04-25)


### Code Refactoring

* provider.registerGrantType accepts the handler directly ([e822918](https://github.com/panva/node-oidc-provider/commit/e822918))


### Features

* added EdDSA support ([2cdb0a2](https://github.com/panva/node-oidc-provider/commit/2cdb0a2))
* added postLogoutSuccessSource helper for logouts without redirects ([a979af8](https://github.com/panva/node-oidc-provider/commit/a979af8))


### BREAKING CHANGES

* `postLogoutRedirectUri` configuration option is removed
in favour of `postLogoutSuccessSource`. This is used to render a success
page out of the box rather then redirecting nowhere.
* node.js minimal version is now v12.0.0 due to its added
EdDSA support (crypto.sign, crypto.verify and EdDSA key objects)
* since provider is now available on `ctx.oidc.provider`
the registerGrantType now expects the second argument to be the handler
directly



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
