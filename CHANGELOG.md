# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [6.18.2](https://github.com/panva/node-oidc-provider/compare/v6.18.1...v6.18.2) (2020-01-16)


### Bug Fixes

* number of default should-change notices using a wrong property ([8e51724](https://github.com/panva/node-oidc-provider/commit/8e5172481181e9b113d7bca20654b9dc230b6d1b))
* principal-change triggered logout fixes ([fa860cf](https://github.com/panva/node-oidc-provider/commit/fa860cfbdaaf3ca9ab46117d1d2673593724f3f3)), closes [#628](https://github.com/panva/node-oidc-provider/issues/628) [#600](https://github.com/panva/node-oidc-provider/issues/600)



## [6.18.1](https://github.com/panva/node-oidc-provider/compare/v6.18.0...v6.18.1) (2020-01-07)


### Bug Fixes

* fix client secret based algorithm keys for clients with jwks ([75d82a0](https://github.com/panva/node-oidc-provider/commit/75d82a0402194393058a2973bce286f1571323d7))



# [6.18.0](https://github.com/panva/node-oidc-provider/compare/v6.17.7...v6.18.0) (2019-12-31)


### Features

* update PAR implementation to an ietf WG draft version ([d3a772b](https://github.com/panva/node-oidc-provider/commit/d3a772bd806f47ec046856fdfb779d2bb3cb5184))



## [6.17.7](https://github.com/panva/node-oidc-provider/compare/v6.17.6...v6.17.7) (2019-12-28)


### Bug Fixes

* **typescript:** rotateRefreshToken boolean, ES256K, async customizers ([22ab1e3](https://github.com/panva/node-oidc-provider/commit/22ab1e3925419956256634e535f15fe3efea9471))



## [6.17.6](https://github.com/panva/node-oidc-provider/compare/v6.17.5...v6.17.6) (2019-12-17)


### Bug Fixes

* skip JWT validating iat is in the past when exp is present ([a7dd855](https://github.com/panva/node-oidc-provider/commit/a7dd85560774c098b15f1aedf7e4dfcc9bc498c1))



## [6.17.5](https://github.com/panva/node-oidc-provider/compare/v6.17.4...v6.17.5) (2019-12-16)


### Bug Fixes

* properly handle routes ending with a trailing slash (again) ([d8a3a67](https://github.com/panva/node-oidc-provider/commit/d8a3a678d8bdd963a2e148fbc333018a67a392b6))



## [6.17.4](https://github.com/panva/node-oidc-provider/compare/v6.17.3...v6.17.4) (2019-12-13)


### Bug Fixes

* properly handle routes ending with a trailing slash ([c4b06de](https://github.com/panva/node-oidc-provider/commit/c4b06de8911b18319f2a94a560c498ffdea864f8))



## [6.17.3](https://github.com/panva/node-oidc-provider/compare/v6.17.2...v6.17.3) (2019-12-09)


### Bug Fixes

* allow empty body without content-type on userinfo ([d5148ad](https://github.com/panva/node-oidc-provider/commit/d5148ad6149672cf93851f0e0e6d72ddedd09ec3))



## [6.17.2](https://github.com/panva/node-oidc-provider/compare/v6.17.1...v6.17.2) (2019-12-07)


### Bug Fixes

* forbid "none" id token algorithm when backchannel logout is used ([797919e](https://github.com/panva/node-oidc-provider/commit/797919e0f770587398490311dfece20fa5745b33))



## [6.17.1](https://github.com/panva/node-oidc-provider/compare/v6.17.0...v6.17.1) (2019-12-05)


### Bug Fixes

* registered native loopback redirect_uris do not get normalized ([96e035f](https://github.com/panva/node-oidc-provider/commit/96e035fca7b504b8bdb6323b33ae58b5220938ce))



# [6.17.0](https://github.com/panva/node-oidc-provider/compare/v6.16.1...v6.17.0) (2019-12-02)


### Features

* add support for secp256k1 elliptic curve use ([30aa706](https://github.com/panva/node-oidc-provider/commit/30aa70621edb158d5cbea67b47c43db81ecf3f90))



## [6.16.1](https://github.com/panva/node-oidc-provider/compare/v6.16.0...v6.16.1) (2019-11-26)


### Bug Fixes

* use shake256(m, 114) for Ed448 ID Token `*_hash` claims ([7e6ba6f](https://github.com/panva/node-oidc-provider/commit/7e6ba6f42d1e25dde9c112e8098dbdafecc7f9c3))



# [6.16.0](https://github.com/panva/node-oidc-provider/compare/v6.15.2...v6.16.0) (2019-11-16)


### Features

* add script tag nonce resolution helper for session management and wmrm ([#584](https://github.com/panva/node-oidc-provider/issues/584)) ([b32b8e6](https://github.com/panva/node-oidc-provider/commit/b32b8e63595d30771520473f7c1a821fb40337af)), closes [#583](https://github.com/panva/node-oidc-provider/issues/583)



## [6.15.2](https://github.com/panva/node-oidc-provider/compare/v6.15.1...v6.15.2) (2019-11-15)


### Bug Fixes

* ensure BaseModel descendants have an exp property ([22cc547](https://github.com/panva/node-oidc-provider/commit/22cc547ffb45503cf2fc4357958325e0f5ed4b2f)), closes [#580](https://github.com/panva/node-oidc-provider/issues/580)



## [6.15.1](https://github.com/panva/node-oidc-provider/compare/v6.15.0...v6.15.1) (2019-11-14)



# [6.15.0](https://github.com/panva/node-oidc-provider/compare/v6.14.2...v6.15.0) (2019-11-14)


### Bug Fixes

* regression introduced in 58f7348 ([4738a8b](https://github.com/panva/node-oidc-provider/commit/4738a8b68c2cbc6c15a1352d2c22ebba7bda839a))


### Features

* add jwsreq Accept value to request_uri resolver ([cec4016](https://github.com/panva/node-oidc-provider/commit/cec4016e001d510e2ca861b4fa4f833d7ddb10a4))
* expose client schema invalidate(err, code) to enable customization ([d672ee8](https://github.com/panva/node-oidc-provider/commit/d672ee83b2daccfc5ca6f59ca996425ed4e410f5))



## [6.14.2](https://github.com/panva/node-oidc-provider/compare/v6.14.1...v6.14.2) (2019-11-10)


### Bug Fixes

* ignore httpOnly and domain configuration options for resume cookies ([952d68e](https://github.com/panva/node-oidc-provider/commit/952d68e3ea559b9b391c17d84573d7fad250f456)), closes [#574](https://github.com/panva/node-oidc-provider/issues/574)



## [6.14.1](https://github.com/panva/node-oidc-provider/compare/v6.14.0...v6.14.1) (2019-11-07)


### Bug Fixes

* handle DPoP htu validation when mounted in express ([f34526c](https://github.com/panva/node-oidc-provider/commit/f34526c31cfdf5ea1111b36cf44c20afc1a53e76)), closes [#572](https://github.com/panva/node-oidc-provider/issues/572)
* use sha512 for Ed25519 and shake256 for Ed448 ID Token `*_hash` claims ([fd3c9e9](https://github.com/panva/node-oidc-provider/commit/fd3c9e9ca41107140054e6632081b1c685e2d767))



# [6.14.0](https://github.com/panva/node-oidc-provider/compare/v6.13.0...v6.14.0) (2019-11-07)


### Bug Fixes

* autosubmit logout when there's no accountId in the session ([c6b1770](https://github.com/panva/node-oidc-provider/commit/c6b1770e68224b7463c1fa5c64199f0cd38131af)), closes [#566](https://github.com/panva/node-oidc-provider/issues/566)
* omit `*_hash` ID Token claims if signed with "none" (code flow only) ([5c540c0](https://github.com/panva/node-oidc-provider/commit/5c540c06ae11bb5ae62eb6f14b7cac66d09f2fa5))


### Features

* add interaction<>session consistency checks ([018255e](https://github.com/panva/node-oidc-provider/commit/018255ed3547667464f1f2837561db593c33bfe8))



# [6.13.0](https://github.com/panva/node-oidc-provider/compare/v6.12.13...v6.13.0) (2019-10-31)


### Features

* update DPoP implementation to indivudal draft 03 ([a7f5d7d](https://github.com/panva/node-oidc-provider/commit/a7f5d7d5459da2ef113eff10767e40aa9dc5bf74))



## [6.12.13](https://github.com/panva/node-oidc-provider/compare/v6.12.12...v6.12.13) (2019-10-24)


### Bug Fixes

* respect mountPath when rendering device flow html views ([74b434c](https://github.com/panva/node-oidc-provider/commit/74b434c627248c82ca9db5aed3a03f0acd0d7214)), closes [#561](https://github.com/panva/node-oidc-provider/issues/561)



## [6.12.12](https://github.com/panva/node-oidc-provider/compare/v6.12.11...v6.12.12) (2019-10-23)


### Bug Fixes

* **typescript:** add findByUserCode to DeviceCode types ([df58cff](https://github.com/panva/node-oidc-provider/commit/df58cff1ac6856942e6da9bba0eaf66d9c216147))
* remove registration access token when client is deleted ([e24ad4a](https://github.com/panva/node-oidc-provider/commit/e24ad4a0fa3c15b875c8aae1ba6fb7e5c1e185f0)), closes [#555](https://github.com/panva/node-oidc-provider/issues/555)

## [6.12.11](https://github.com/panva/node-oidc-provider/compare/v6.12.10...v6.12.11) (2019-10-20)


### Bug Fixes

* **typescript:** allow registration policies type to be async ([0a46a65](https://github.com/panva/node-oidc-provider/commit/0a46a65)), closes [#551](https://github.com/panva/node-oidc-provider/issues/551)



## [6.12.10](https://github.com/panva/node-oidc-provider/compare/v6.12.9...v6.12.10) (2019-10-15)


### Bug Fixes

* **cookies:** use ctx.secure from the mount context when available ([c8d8fe6](https://github.com/panva/node-oidc-provider/commit/c8d8fe6))



## [6.12.9](https://github.com/panva/node-oidc-provider/compare/v6.12.8...v6.12.9) (2019-10-14)


### Bug Fixes

* mounted devInteractions now honour the mount path ([8fb8af5](https://github.com/panva/node-oidc-provider/commit/8fb8af5)), closes [#549](https://github.com/panva/node-oidc-provider/issues/549) [#548](https://github.com/panva/node-oidc-provider/issues/548)



## [6.12.8](https://github.com/panva/node-oidc-provider/compare/v6.12.7...v6.12.8) (2019-10-14)


### Bug Fixes

* **typescript:** add missing OIDCContext cookies property ([0c04af6](https://github.com/panva/node-oidc-provider/commit/0c04af6))



## [6.12.7](https://github.com/panva/node-oidc-provider/compare/v6.12.5...v6.12.7) (2019-10-09)


### Bug Fixes

* forbid redirect_uri with an empty fragment component ([ca196a0](https://github.com/panva/node-oidc-provider/commit/ca196a0))
* v6.12.6 native app uris regression fixed ([fd56ef6](https://github.com/panva/node-oidc-provider/commit/fd56ef6))



## [6.12.5](https://github.com/panva/node-oidc-provider/compare/v6.12.4...v6.12.5) (2019-10-04)


### Bug Fixes

* add missing constructor to index.d.ts ([#542](https://github.com/panva/node-oidc-provider/issues/542)) ([a5621a4](https://github.com/panva/node-oidc-provider/commit/a5621a4))



## [6.12.4](https://github.com/panva/node-oidc-provider/compare/v6.12.3...v6.12.4) (2019-10-03)


### Bug Fixes

* **typescript:** revert void/undefined changes from 6.12.3 ([e0bbaae](https://github.com/panva/node-oidc-provider/commit/e0bbaae)), closes [#541](https://github.com/panva/node-oidc-provider/issues/541)



## [6.12.3](https://github.com/panva/node-oidc-provider/compare/v6.12.2...v6.12.3) (2019-10-01)


### Bug Fixes

* use updated jose package ([ee17022](https://github.com/panva/node-oidc-provider/commit/ee17022))
* **typescript:** fix void/undefined inconsistencies and ts lint ([96c9415](https://github.com/panva/node-oidc-provider/commit/96c9415))



## [6.12.2](https://github.com/panva/node-oidc-provider/compare/v6.12.1...v6.12.2) (2019-09-28)


### Bug Fixes

* do not send empty secret to adapter in a DCR edge case ([af9ecd9](https://github.com/panva/node-oidc-provider/commit/af9ecd9))



## [6.12.1](https://github.com/panva/node-oidc-provider/compare/v6.12.0...v6.12.1) (2019-09-27)


### Bug Fixes

* fixed session management state fallback cookie name ([91b0dea](https://github.com/panva/node-oidc-provider/commit/91b0dea))



# [6.12.0](https://github.com/panva/node-oidc-provider/compare/v6.11.1...v6.12.0) (2019-09-27)


### Features

* handle sameSite=none incompatible user-agents ([4e68415](https://github.com/panva/node-oidc-provider/commit/4e68415))



## [6.11.1](https://github.com/panva/node-oidc-provider/compare/v6.11.0...v6.11.1) (2019-09-24)


### Bug Fixes

* **typescript:** provider.callback getter type regression fixed ([5cea116](https://github.com/panva/node-oidc-provider/commit/5cea116)), closes [#534](https://github.com/panva/node-oidc-provider/issues/534)



# [6.11.0](https://github.com/panva/node-oidc-provider/compare/v6.10.0...v6.11.0) (2019-09-24)


### Bug Fixes

* token TTL being a helper function is now accepted ([a930355](https://github.com/panva/node-oidc-provider/commit/a930355))


### Features

* default refresh token TTL policy for SPAs follows the updated BCP ([d6a2a34](https://github.com/panva/node-oidc-provider/commit/d6a2a34))
* update JWT Response for OAuth Token Introspection to draft 08 ([5f917e2](https://github.com/panva/node-oidc-provider/commit/5f917e2))



# [6.10.0](https://github.com/panva/node-oidc-provider/compare/v6.9.0...v6.10.0) (2019-09-21)


### Bug Fixes

* **typescript:** add missing definitions ([#533](https://github.com/panva/node-oidc-provider/issues/533)) ([c663417](https://github.com/panva/node-oidc-provider/commit/c663417))


### Features

* update FAPI RW behaviours ([a7ed27a](https://github.com/panva/node-oidc-provider/commit/a7ed27a))
* update pushed authorization requests draft ([aaf5740](https://github.com/panva/node-oidc-provider/commit/aaf5740))



# [6.9.0](https://github.com/panva/node-oidc-provider/compare/v6.8.0...v6.9.0) (2019-09-17)


### Features

* added TypeScript definitions ([#530](https://github.com/panva/node-oidc-provider/issues/530)) ([5adf5a8](https://github.com/panva/node-oidc-provider/commit/5adf5a8))



# [6.8.0](https://github.com/panva/node-oidc-provider/compare/v6.7.0...v6.8.0) (2019-09-06)


### Features

* update fapiRW draft feature ([8b927fc](https://github.com/panva/node-oidc-provider/commit/8b927fc))
* update pushed request objects to b6cd952 ([43fa8aa](https://github.com/panva/node-oidc-provider/commit/43fa8aa))



# [6.7.0](https://github.com/panva/node-oidc-provider/compare/v6.6.2...v6.7.0) (2019-08-30)


### Bug Fixes

* correct ssl offloading proxy documentation url in console warning ([b871e99](https://github.com/panva/node-oidc-provider/commit/b871e99))
* handle server_error on expired unsigned request objects ([7172a85](https://github.com/panva/node-oidc-provider/commit/7172a85))
* ignore secret and expiration timestamp on dynamic create edge case ([d532fb2](https://github.com/panva/node-oidc-provider/commit/d532fb2))


### Features

* allow authorization requests with only a Request Object ([e3fa143](https://github.com/panva/node-oidc-provider/commit/e3fa143))
* allow structured access token customizations ([4be3bb2](https://github.com/panva/node-oidc-provider/commit/4be3bb2)), closes [#520](https://github.com/panva/node-oidc-provider/issues/520)
* experimental support for pushed request objects ([4ac3905](https://github.com/panva/node-oidc-provider/commit/4ac3905))
* strategies for parameter merging Request Object <> OAuth 2.0 ([3ad1744](https://github.com/panva/node-oidc-provider/commit/3ad1744))
* support non-0 expiring client secrets (client_secret_expires_at) ([02877f6](https://github.com/panva/node-oidc-provider/commit/02877f6))



## [6.6.2](https://github.com/panva/node-oidc-provider/compare/v6.6.1...v6.6.2) (2019-08-26)


### Bug Fixes

* do not use mounted app's ctx.cookies ([ce0c06d](https://github.com/panva/node-oidc-provider/commit/ce0c06d)), closes [#517](https://github.com/panva/node-oidc-provider/issues/517)



## [6.6.1](https://github.com/panva/node-oidc-provider/compare/v6.6.0...v6.6.1) (2019-08-25)


### Bug Fixes

* extend interactionDetails to allow (req, res) ([e1d69cf](https://github.com/panva/node-oidc-provider/commit/e1d69cf)), closes [#517](https://github.com/panva/node-oidc-provider/issues/517)



# [6.6.0](https://github.com/panva/node-oidc-provider/compare/v6.5.0...v6.6.0) (2019-08-23)


### Bug Fixes

* properly apply samesite=none for non-webkit browsers ([ec2ffc6](https://github.com/panva/node-oidc-provider/commit/ec2ffc6))


### Features

* added Node.js lts/dubnium support ([52e914c](https://github.com/panva/node-oidc-provider/commit/52e914c))



# [6.5.0](https://github.com/panva/node-oidc-provider/compare/v6.4.2...v6.5.0) (2019-08-20)


### Bug Fixes

* empty params are handled as if they were not provided at all ([a9e0f8c](https://github.com/panva/node-oidc-provider/commit/a9e0f8c))


### Features

* basic and post client auth methods are now interchangeable ([a019fc9](https://github.com/panva/node-oidc-provider/commit/a019fc9))
* enable RSA-OAEP-256 when node runtime supports it ([cfada87](https://github.com/panva/node-oidc-provider/commit/cfada87))
* new experimental support for FAPI RW Security Profile added ([0c69553](https://github.com/panva/node-oidc-provider/commit/0c69553))
* RFC8628 has been published, device flow is now a stable feature ([98a3bd4](https://github.com/panva/node-oidc-provider/commit/98a3bd4))



## [6.4.2](https://github.com/panva/node-oidc-provider/compare/v6.4.1...v6.4.2) (2019-08-18)


### Bug Fixes

* make structured token's end-user "sub" pairwise if configured ([24a08c2](https://github.com/panva/node-oidc-provider/commit/24a08c2))
* use correct postLogoutRedirectUri for resume's logout when mounted ([a72b27d](https://github.com/panva/node-oidc-provider/commit/a72b27d))



## [6.4.1](https://github.com/panva/node-oidc-provider/compare/v6.4.0...v6.4.1) (2019-08-13)


### Bug Fixes

* bring paseto token claims inline with jwt-ietf ([265e400](https://github.com/panva/node-oidc-provider/commit/265e400))



# [6.4.0](https://github.com/panva/node-oidc-provider/compare/v6.3.0...v6.4.0) (2019-08-07)


### Bug Fixes

* paseto formatted access token audience is a single string ([1fd45f5](https://github.com/panva/node-oidc-provider/commit/1fd45f5))
* properly check if resourceIndicators is enabled ([bbcdca2](https://github.com/panva/node-oidc-provider/commit/bbcdca2))


### Features

* added a helper for validating provided resource indicator values ([a97ffdc](https://github.com/panva/node-oidc-provider/commit/a97ffdc)), closes [#487](https://github.com/panva/node-oidc-provider/issues/487)
* allow audiences helper to return a single string audience ([4c7a3a8](https://github.com/panva/node-oidc-provider/commit/4c7a3a8))
* draft implementation of IETF JWT Access Token profile ([e690462](https://github.com/panva/node-oidc-provider/commit/e690462))



# [6.3.0](https://github.com/panva/node-oidc-provider/compare/v6.2.2...v6.3.0) (2019-08-04)


### Features

* new option for resolving JWT Access Token signing algorithm ([28e85ef](https://github.com/panva/node-oidc-provider/commit/28e85ef))



## [6.2.2](https://github.com/panva/node-oidc-provider/compare/v6.2.1...v6.2.2) (2019-08-02)


### Bug Fixes

* do not assign the defaulted to response_mode to params ([18867ad](https://github.com/panva/node-oidc-provider/commit/18867ad))
* dynamic format gets a ctx as a first argument as documented ([f62eb4b](https://github.com/panva/node-oidc-provider/commit/f62eb4b))



## [6.2.1](https://github.com/panva/node-oidc-provider/compare/v6.2.0...v6.2.1) (2019-07-25)


### Bug Fixes

* bump dependencies and compatible draft versions ([97738e3](https://github.com/panva/node-oidc-provider/commit/97738e3))
* revert missing mTLS cert errors to invalid_grant ([afac459](https://github.com/panva/node-oidc-provider/commit/afac459))



# [6.2.0](https://github.com/panva/node-oidc-provider/compare/v6.1.2...v6.2.0) (2019-07-21)


### Features

* mTLS stable release candidate ([a999452](https://github.com/panva/node-oidc-provider/commit/a999452))



## [6.1.2](https://github.com/panva/node-oidc-provider/compare/v6.1.1...v6.1.2) (2019-07-12)


### Bug Fixes

* acknowledging tls client auth draft fixed ([02df82a](https://github.com/panva/node-oidc-provider/commit/02df82a))



## [6.1.1](https://github.com/panva/node-oidc-provider/compare/v6.1.0...v6.1.1) (2019-07-12)


### Bug Fixes

* bump acknowledgable draft versions that don't need code changes ([55b4770](https://github.com/panva/node-oidc-provider/commit/55b4770))



# [6.1.0](https://github.com/panva/node-oidc-provider/compare/v6.0.3...v6.1.0) (2019-07-10)


### Bug Fixes

* authorization header scheme is checked case-insensitive ([773ec52](https://github.com/panva/node-oidc-provider/commit/773ec52))
* block static client registration read action (edgiest of cases) ([18db430](https://github.com/panva/node-oidc-provider/commit/18db430))
* update dependencies, plug reported lodash vulnerability ([a2cdfd0](https://github.com/panva/node-oidc-provider/commit/a2cdfd0))


### Features

* add experimental support for DPoP ([61edb8c](https://github.com/panva/node-oidc-provider/commit/61edb8c))



## [6.0.3](https://github.com/panva/node-oidc-provider/compare/v6.0.2...v6.0.3) (2019-07-04)


### Bug Fixes

* default renderError page escapes error props inherited from params ([6aedbab](https://github.com/panva/node-oidc-provider/commit/6aedbab)), closes [#489](https://github.com/panva/node-oidc-provider/issues/489)



## [6.0.2](https://github.com/panva/node-oidc-provider/compare/v6.0.1...v6.0.2) (2019-07-03)


### Bug Fixes

* device flow refresh tokens for public clients are now be certificate bound as well ([904ad2d](https://github.com/panva/node-oidc-provider/commit/904ad2d))



## [6.0.1](https://github.com/panva/node-oidc-provider/compare/v6.0.0...v6.0.1) (2019-06-29)


### Bug Fixes

* correctly apply mergeWithLastSubmission for interactionFinished ([eb67723](https://github.com/panva/node-oidc-provider/commit/eb67723))



# [6.0.0](https://github.com/panva/node-oidc-provider/compare/v5.5.5...v6.0.0) (2019-06-28)

This release has been on and off in development since the major v5.x release in September 2018, it
is the biggest and most breaking release to date and a massive accomplishment, most of the new
features you saw added to the v5.x release line have been backports from a privately worked on v6.x
branch of the project.

> ~ 334 changed files with 19,617 additions and 13,322 deletions.

With the API just slightly evolving with each version for over more than 3 years it was in need of
a big overhaul, albeit in the configuration or adapter API department. Knowing the next release is a
breaking one just welcomed innovation and refactoring, hence the endless stream of alpha and beta
releases with breaking changes in them.

## Notable changes

### Fully embraced browser based apps using Authorization Code flow + PKCE

> Browser-based public clients are now able to get Refresh Tokens that are
> not `offline_access`, are end-user session bound and rotate with each use.
>
> This is in line with the BCPs being worked on by the OAuth WG and it is
> also ready for new sender-constraining mechanisms such as DPoP being
> implemented as soon as they are adopted as WG drafts.
>
> Issuing refresh tokens without `offline_access` is not enabled by default
> and is controlled by a new `issueRefreshToken` configuration policy.
>
> By default all tokens that do not have `offline_access` scope are now
> handled as invalid or expired when the session they came from is gone,
> i.e. when the end-user logs out or a shorter-lived session simply expires
> due to inactivity. This behaviour is controled by a new `expiresWithSession`
> configuration policy.

### CORS is not an afterthought

> Also related to browser based apps using the AS. It is now possible to
> have CORS control per request and implement request context based policies
> using new `clientBasedCORS` configuration policy. By default this policy's
> value enables * CORS on all CORS-intended endpoints.
>
> You can see a client-metadata based approach in [/recipes](/recipes).

### Authorization Requests without the openid scope

> The provider can now process authorization requests that do not contain
> the `openid` scope, pure OAuth 2.0 mode.

### Optimized crypto

> All crypto is now done using node's `crypto` module with the use KeyObject
> keys and secrets.
> Node.js >= 12.0.0 added a KeyObject class to represent a symmetric or
> asymmetric key
> and it is recommended that applications to use this new KeyObject API instead
> of passing keys as strings or Buffers due to improved security features
> as well as optimized operation.

### EdDSA & PASETO

> The provider can now sign ID Tokens, JWT Access Tokens, Userinfo and
> everything JOSE using [EdDSA](https://ed25519.cr.yp.to/).  
> With Ed25519 now being supported you can also have your Access Tokens in
> [PASETO](https://paseto.io) format.

## Upgrade / Migration path

5 -> 6 migration path is not clearly laid out, i'd much more recommend starting just with
`new Provider('...')` and then backporting your configuration and code, please note some changed
configuration defaults which, if you relied upon them, you need to now configure to their v5.x
values explicitly. Should you require assistance with an upgrade please don't hesitate to get in
touch via the issue tracker (limited support capacity) or via email for a more direct and involved
conversation.

### Bug Fixes

* fixed symmetric key derivation for JWT introspection endpoint response ([1a50c82](https://github.com/panva/node-oidc-provider/commit/1a50c82))
* fixed symmetric key derivation for JWT authorization endpoint response ([1a50c82](https://github.com/panva/node-oidc-provider/commit/1a50c82))
* `*_jwt` client auth method alg no longer mixes up (a)symmetrical ([1771655](https://github.com/panva/node-oidc-provider/commit/1771655))
* acceptedClaimsFor filtering out claims not scopes ([fd8f886](https://github.com/panva/node-oidc-provider/commit/fd8f886))
* added scope to implicit responses when different from request ([71b2e7e](https://github.com/panva/node-oidc-provider/commit/71b2e7e))
* allow all incoming headers for CORS requests ([3d2c8e4](https://github.com/panva/node-oidc-provider/commit/3d2c8e4))
* also reject client jwks/jwks_uri symmetric keys ([df18f62](https://github.com/panva/node-oidc-provider/commit/df18f62)), closes [#481](https://github.com/panva/node-oidc-provider/issues/481)
* avoid sending "samesite=none" to webkit browsers due to their bug ([9c6e05b](https://github.com/panva/node-oidc-provider/commit/9c6e05b))
* base accepted scope off the accepted scopes, not param scopes ([ccec5d3](https://github.com/panva/node-oidc-provider/commit/ccec5d3))
* break endless login loop with too short max_age values ([66c7968](https://github.com/panva/node-oidc-provider/commit/66c7968))
* check id_token_hint even if the interaction check is disabled ([7528220](https://github.com/panva/node-oidc-provider/commit/7528220))
* check PKCE verifier and challenge ABNF, remove it from device flow ([849b964](https://github.com/panva/node-oidc-provider/commit/849b964))
* check sameSite cookie option for none case-insensitive ([523d1b2](https://github.com/panva/node-oidc-provider/commit/523d1b2))
* client key agreement with ECDH-ES is not possible in two cases ([5c39f6e](https://github.com/panva/node-oidc-provider/commit/5c39f6e))
* clientDefaults is now used in resolving defaults of some edge props ([e7bcfd2](https://github.com/panva/node-oidc-provider/commit/e7bcfd2))
* correctly use the secret value, not its SHA digest, for PBES2-* ([43256ba](https://github.com/panva/node-oidc-provider/commit/43256ba))
* device flow - mark codes as already used at the right time ([7b913fd](https://github.com/panva/node-oidc-provider/commit/7b913fd))
* do not send empty error_descriptions with some responses ([663fadc](https://github.com/panva/node-oidc-provider/commit/663fadc))
* enable debugging session bound tokens not being returned ([cc66876](https://github.com/panva/node-oidc-provider/commit/cc66876))
* enable Secure cookies with the default settings if on secure req ([a056bfd](https://github.com/panva/node-oidc-provider/commit/a056bfd))
* expose correct discovery metadata jwt introspection signing algs ([cf4e442](https://github.com/panva/node-oidc-provider/commit/cf4e442)), closes [#475](https://github.com/panva/node-oidc-provider/issues/475)
* fail logout when post_logout_redirect_uri is not actionable ([b3a50ac](https://github.com/panva/node-oidc-provider/commit/b3a50ac))
* handle client jwks x5c when kty is OKP, use client jwks key_ops ([f052f6b](https://github.com/panva/node-oidc-provider/commit/f052f6b))
* handle invalid interaction policies with access_denied ([1b6104c](https://github.com/panva/node-oidc-provider/commit/1b6104c))
* html-rendered response modes now honour 400 and 500 status codes ([9771581](https://github.com/panva/node-oidc-provider/commit/9771581))
* jwt client assertion audience now also accepts issuer and token url ([38706e7](https://github.com/panva/node-oidc-provider/commit/38706e7))
* rendered OP views are no longer dead ends with javascript disabled ([c2f17d7](https://github.com/panva/node-oidc-provider/commit/c2f17d7))
* request object processing order related and general fixes ([9fd3fba](https://github.com/panva/node-oidc-provider/commit/9fd3fba))
* session required client properties control the iss & sid return ([ab08cbe](https://github.com/panva/node-oidc-provider/commit/ab08cbe))
* short cookie options dont affect the resume cookie path scope ([4c7e877](https://github.com/panva/node-oidc-provider/commit/4c7e877))
* use fixed scope to claim mapping over dynamic ones ([03a6130](https://github.com/panva/node-oidc-provider/commit/03a6130)), closes [#466](https://github.com/panva/node-oidc-provider/issues/466)
* subsequent authorization requests for the same combination of client, end-user and sessionUid will
  all have the same `grantId` value now
* `PKCE` is no longer forced for `grant_type=urn:ietf:params:oauth:grant-type:device_code`
* response_type `code token` no longer requires nonce parameter to be present. See
  [OIDC Core 1.0 Errata 2 changeset](https://bitbucket.org/openid/connect/commits/31240ed1f177b16b589b54c3795ea0187fa5b85e)
* provider no longer reject client registration when the `jwks.keys` is empty
* provider now rejects client's `jwks` and `jwks_uri` if they contain private key or symmetric key material. See
  [OIDC Core 1.0 Errata 2 changeset](https://bitbucket.org/openid/connect/commits/f91efe0f583d9e8a96a7717f454e1822041feb14)
* Client will no longer be looked up twice during failed authorization due to client not being found
* `max_age` parameter is now validated to be a non-negative safe integer
* client secrets no longer need to have minimal length to support HS signing
* established session acr/amr is now available for any authorization request, not just the one it
  was established with


### Code Refactoring

* change certificates to jwks ([a75e478](https://github.com/panva/node-oidc-provider/commit/a75e478))
* consolidate interaction policy and url configuration ([5c0ba04](https://github.com/panva/node-oidc-provider/commit/5c0ba04))
* disable "token" including response types defaults ([78e4ebb](https://github.com/panva/node-oidc-provider/commit/78e4ebb))
* merge interactions and interactionUrl configuration ([1193719](https://github.com/panva/node-oidc-provider/commit/1193719))
* provider.registerGrantType accepts the handler directly ([e822918](https://github.com/panva/node-oidc-provider/commit/e822918))
* remove provider.initialize() ([ec71ed0](https://github.com/panva/node-oidc-provider/commit/ec71ed0))
* remove request/request http client handling and methods ([683e6c2](https://github.com/panva/node-oidc-provider/commit/683e6c2))
* rename findById to findAccount to follow the helper convention ([43f5ecc](https://github.com/panva/node-oidc-provider/commit/43f5ecc))
* rename idToken.sign to idToken.issue ([1c6d556](https://github.com/panva/node-oidc-provider/commit/1c6d556))


### Features

* added support for direct symmetric key encryption alg 'dir' ([1a50c82](https://github.com/panva/node-oidc-provider/commit/1a50c82))
* added extraAccessTokenClaims configuration option ([25915ef](https://github.com/panva/node-oidc-provider/commit/25915ef))
* added options to disable userinfo and userinfo jwt responses ([3620aed](https://github.com/panva/node-oidc-provider/commit/3620aed))
* added per-request http options helper function configuration ([4aee414](https://github.com/panva/node-oidc-provider/commit/4aee414))
* added v2.public PASETOs as an available issued token format ([7b149cf](https://github.com/panva/node-oidc-provider/commit/7b149cf))
* added EdDSA support ([2cdb0a2](https://github.com/panva/node-oidc-provider/commit/2cdb0a2))
* added postLogoutSuccessSource helper for logouts without redirects ([a979af8](https://github.com/panva/node-oidc-provider/commit/a979af8))
* allow for client default metadata to be changed ([8f20a69](https://github.com/panva/node-oidc-provider/commit/8f20a69))
* allow non-conform instances ([f772f97](https://github.com/panva/node-oidc-provider/commit/f772f97))
* always return scope with token implicit response ([ea7b394](https://github.com/panva/node-oidc-provider/commit/ea7b394))
* default refresh token rotation policy changed ([7310765](https://github.com/panva/node-oidc-provider/commit/7310765))
* discovery must now always be enabled ([5c3c0c7](https://github.com/panva/node-oidc-provider/commit/5c3c0c7))
* enable client-based CORS origin whitelisting ([8b4fd9e](https://github.com/panva/node-oidc-provider/commit/8b4fd9e))
* passthrough cors middleware if pre-existing headers are present ([6ec09ef](https://github.com/panva/node-oidc-provider/commit/6ec09ef)), closes [#447](https://github.com/panva/node-oidc-provider/issues/447)
* replay prevention for client assertions is now built in ([a22d6ce](https://github.com/panva/node-oidc-provider/commit/a22d6ce))
* request objects are now one-time use if they have iss, jti and exp ([1dc44dd](https://github.com/panva/node-oidc-provider/commit/1dc44dd))
* set default sameSite cookie values, short: lax, long: none ([cfb1a70](https://github.com/panva/node-oidc-provider/commit/cfb1a70))
* it is now possible to issue Refresh Tokens without the offline_access scope, these refresh tokens
  and all access tokens issued from it will be unusable when the session they're tied to gets
  removed or its subject changes
  * Session now has a `uid` property which persists throughout the cookie identifier rotations and
    its value is stored in the related tokens as `sessionUid`, it is based on this value that the
    provider will perform session lookups to ensure that session bound tokens are still considered
    valid
  * by default a session bound grant is one without offline_access, this can be changed, or
    completely disabled to restore previous behaviour with a new `expiresWithSession` helper
* `issueRefreshToken` configuration helper has been added, it allows to define specific client and
  context based policy about whether a refresh token should be issued or not to a client
* interactions will now be requested multiple times if the authorization request context cannot be
  resolved yet. This means you can now resolve one prompt at a time. When you load the interaction
  details (using `provider.interactionDetails()`), in addition to `details.params` containing the
  complete parsed authorization parameters object, you now also have access to `details.prompt`
  containing an object with the prompt details.
  * `details.prompt.name` has the name prompt, e.g. `login`
  * `details.prompt.reasons` has an array of reasons the prompt is being requested, e.g. `["max_age"]`
  * `details.prompt.details` contains is an object of details you might need to resolve the prompt
  * `details.session` is an object containing details about the OP session as-is at the moment
    of requesting interaction
    * `details.session.uid` is the internal session's uid
    * `details.session.cookie` is the session cookie value
    * `details.session.acr` is the current session's acr if there's one
    * `details.session.amr` is the current session's amr if there's one
    * `details.session.accountId`
* interactions results `consent.rejectedScopes` and `consent.rejectedClaims` will no longer
  replace the existing values, the rejected scopes and claims will accumulate instead, the same
  happens with what's assumed accepted (that is everything thats been requested and wasn't rejected)
* `end_session_endpoint` now accepts a POST with the parameters being in the body of the request,
  this is so that clients avoid URL length limits and exposing PII in the URL. See
  [OIDC Issues tracker](https://bitbucket.org/openid/connect/issues/1056/use-of-id_token-in-rp-initiated-logout-as)
* Updated OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens draft
  implementation - draft 13
  * client's `certificate_bound_access_tokens`, now also binds the Refresh Token if the client is
    using "none" endpoint auth method
  * SAN based client properties are now recognized, they are not however, supported and will throw
    when presented
* Updated Device Flow draft implementation - draft 15
  * the same client authentication as for token_endpoint is now used at the device_authorization_endpoint
  * once a user code passes the device confirmation prompt it cannot be used again
* `end_session_endpoint` is now always available, it is not bound to any of the session or logout
  specification features
* clients may now have a `scope` property, when set authorization requests for this client
  must stay within those whitelisted scopes
* `end_session_endpoint` will now drop session-bound tokens for the clients/grants encountered
  in the session
* when the existing session's subject (end-user identifier) differs from one inside interaction
  results the provider will bounce the user agent through the end_session_endpoint to perform a
  "clean" logout - drop the session, perform front and back-channel logout notifications (if
  enabled) and revoke grants (if bound to session)
* end session endpoint will now revoke tokens bound to the user-agent session by grantId for the
  clients that have had their authorization removed
* `rotateRefreshToken` configuration added, it can be a function to allow for client and context
  based policy for deciding whether refresh token should rotated or not
* the provider can now process non-openid authorization requests
  * requests without an `openid` scope or `scope` parameter altogether will be processed as plain
    OAuth2.0 authorization requests
  * this has a few exceptions:
    * response types that include id_token still require the `openid` scope
    * use of openid feature related parameters such as `claims`, `acr_values`, `id_token_hint` and
      `max_age` still require the `openid` scope
    * use of openid feature related client attributes such as `default_acr_values`,
      `default_max_age`, `require_auth_time` still require the `openid` scope
  * use of the `userinfo_endpoint` is only possible with access tokens that have the `openid` scope
  * note: the scope claim in JWT access tokens will be missing if the parameter was missing as well,
    dtto for the scope property in your persitent storage
* authorization parameter `max_age=0` now behaves like `prompt=login` (dtto client's
  `default_max_age=0`)
* every model now has its own `saved` and `destroyed` event emitted by the provider, sessions and
  interactions too, the convention is `{snake_cased_model_name}.{saved|destroyed}`
* `urn:` request_uri support added, provided that one overloads
  `provider.Client.prototype.requestUriAllowed` and `provider.requestUriCache.resolveUrn`
* `http:` request_uris are now allowed under the assumption that the request object it yields is
  verifiable (signed and/or symmetrically encrypted)
* added `invalid_software_statement` and `unapproved_software_statement` exported errors


### BREAKING CHANGES

* node.js minimal version is now v12.0.0 due to its added
EdDSA support (crypto.sign, crypto.verify and EdDSA key objects)
* the default enabled response types now omit all that
result in access tokens being issued by the authorization endpoint
and delivered via a fragment. If you're upgrading just configure
`responseTypes` to include the ones you need for legacy purposes.
* `interactionUrl` is now `interactions.url`
* `interactionCheck` has been removed and replaced with a new format
option`interactions.policy`
* `interactionUrl` configuration option is now
`interactions.url`
* the route name for jwks_uri is now `jwks` (was
`certificates`). If you're upgrading and use a custom path for
`certificates` make sure to use the `routes.jwks` now to configure the
path
* the default path for route `jwks` (certificates) is now
`/jwks`. If you're upgrading and want to (you probably do) keep using
the old path, make sure to configure `routes.jwks` with the old value
`/certs`
* PBES2-* Content Encryption Key encryption now correctly
uses the  `client_secret` value rather than its SHA digest.
* when neither interactions nor custom middlewares result
in the authorization chain having an account identifier the server will
now resolve the request with access_denied error.
* when neither interactions nor custom middlewares result
in the authorization chain having resolved an accepted scope the server
will now resolve the request with access_denied error.
* default `rotateRefreshToken` configuration value
is now a function with a described policy that follows
[OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13)
* removed features.discovery and it is now always-on, no
point in disabling discovery, ever.
* logoutPendingSource no longer receives a `timeout`
argument
* `provider.defaultHttpOptions` setter was removed, use
the new `httpOptions` configuration helper function instead
* provider now asserts that client's
`backchannel_logout_uri` returns a 200 OK response as per specification.
* provider.IdToken.prototype.sign is renamed to
provider.IdToken.prototype.issue
* PKCE code_challenge and code_verifier is now checked
to be 43-128 characters long and conforms to the allowed character set
of [A-Z] / [a-z] / [0-9] / `-` / `.` / `_` / `~`. PKCE is now also
ignored for the Device Code authorization request and token exchange.
* findById helper was renamed to findAccount
* `postLogoutRedirectUri` configuration option is removed
in favour of `postLogoutSuccessSource`. This is used to render a success
page out of the box rather then redirecting nowhere.
* since provider is now available on `ctx.oidc.provider`
the registerGrantType now expects the second argument to be the handler
directly
* `provider.initialize()` has been removed.
* what was previously passed to `initialize()` as
`keystore` must now be passed as configuration property (as `jwks` and
it must be a JWKS formatted object, no longer a KeyStore instance.
* what was previously passed to `initialize()` as
`clients` must now be passed as configuration property (as `clients`).
These "static" clients are no longer validated during the instantiation
but just like with adapter-loaded clients - when they're first needed.
* what was previously passed to `initialize()` as
`adapter` must now be passed as configuration property (as `adapter`).
* provider will no longer call `adapter`'s `connect`
method.
* Due to request's maintenance mode and inevitable
deprecation (see https://github.com/request/request/issues/3142)
the option to switch the provider to use request has been removed.
* end_session_endpoint will now throw an error when
clients provide post_logout_redirect_uri but fail to provide an
id_token_hint. See https://bitbucket.org/openid/connect/issues/1032
* all exported JWK related methods have been removed
* JWT Access Token can now only be signed using the provider's asymmetric keys, client's HS will no
  longer be used
* `sid` ID Token claim is now only returned when the client requests it using the `claims` parameter
  or has the appropriate back/front channel logout uris enabled and front/backchannel_logout_session_required
  set to true
* clients with `request_object_signing_alg` set must now always provide a request object,
  authorization requests will fail with `invalid_request` when `request` or `request_uri` is missing
  for such clients
* adapter changes to accomodate new functionality
  * it is no longer desired to drop all related tokens when `#destroy` is called
  * Session adapter instance expects to have a `findByUid` method which resolves with the same data
    as `find` does only the reference is the session's `uid` property. This is only needed when
    utilizing the new session-bound tokens
  * AccessToken, RefreshToken, AuthorizationCode & DeviceCode adapter instances expect to have
    `revokeByGrantId` method which accepts a string parameter `grantId` and revokes all tokens
    with its matching value in the `grantId` property
* only `AccessToken` and `ClientCredentials` may have a format. All other tokens are now forced to
  be opaque
* `clientCacheDuration` configuration option and `provider.Client.cacheClear` method have been
  removed, the provider now handles everything internally and Client objects are re-instantiated
  automatically if the client's configuration changes.
* `token.*` events are no longer emitted, instead each token has its own event, sessions and
  interactions too, the convention is `snake_cased_model_name.*`
* `features.pkce` and `features.oauthNativeApps` have been removed and they are always in effect,
  PKCE is always forced on native clients
* `iss` is no longer pushed to token/model storage payloads
* `features.sessionManagement.thirdPartyCheckUrl` has been removed
* `features.alwaysIssueRefresh` has been removed
* `features.refreshTokenRotation` has been renamed to `features.rotateRefreshToken` and its values
  are now true/false or a function that returns true/false when a refresh token should or should not
  be rotated
* `features.conformIdTokenClaims` is not a feature anymore, it is just `conformIdTokenClaims` in the
  configuration object's root
* revoking an Access Token via the `revocation_endpoint` will not revoke the whole grant any more
* default `interaction` cookie name value changed from `_grant` to `_interaction`
* default `resume` cookie name value changed from `_grant` to `_interaction_resume`
* all references to `ctx.oidc.uuid` are now `ctx.oidc.uid` and the format is now a random string,
  not a uuid
* nearly all emitted events have had their arguments shuffled and/or changed to allow for `ctx` to
  be first
* nearly all helper functions have had their arguments shuffled and/or changed to allow for `ctx` to
  be the first amongst them (oh yeah, `ctx` has been added almost everywhere)
* all configuration `features` are no longer booleans, they're objects with all their relevant
  configuration in the `defaults.js` file and `docs/README.md`. Old configuration format is not
  accepted anymore
* some configuration properties that only relate to a specific features were moved from the root
  level to the feature's configuration level and have been renamed, these are
  - `deviceFlowSuccess` -> `features.deviceFlow.successSource`
  - `frontchannelLogoutPendingSource` -> `features.frontchannelLogout.logoutPendingSource`
  - `userCodeConfirmSource` -> `features.deviceFlow.userCodeConfirmSource`
  - `userCodeInputSource` -> `features.deviceFlow.userCodeInputSource`
* Session model has been split to Session and Interaction
* interaction login result now defaults to `remember: true`
* `legacy` storage format has been removed
* adding additional audiences through the `audiences` helper is now only possible for Access Tokens
  (AccessToken and ClientCredentials)
* the `.well-known/webfinger` endpoint that always returned success is removed
* default `deviceFlow.deviceInfo` `userAgent` property is now `ua`


### Other changes / deprecations

* example mongo and redis adapters revised
* example redis with ReJSON module adapter added
* example unmaintained adapters removed



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

* added Resource Indicators for OAuth 2.0 - draft 00 implementation ([1bc2994](https://github.com/panva/node-oidc-provider/commit/1bc2994))



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

* added self_signed_tls_client_auth client authentication method ([9a1f0a3](https://github.com/panva/node-oidc-provider/commit/9a1f0a3))
* added tls_client_auth client authentication method ([ce2bf66](https://github.com/panva/node-oidc-provider/commit/ce2bf66))
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
