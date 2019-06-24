# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

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
* when a symmetric endpoint authentication signing alg
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
