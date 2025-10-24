# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [9.5.2](https://github.com/panva/node-oidc-provider/compare/v9.5.1...v9.5.2) (2025-10-24)


### Refactor

* change new Debug() to debug() ([#1363](https://github.com/panva/node-oidc-provider/issues/1363)) ([b86b47c](https://github.com/panva/node-oidc-provider/commit/b86b47ca654d61bebff79d318bea42bec1e36c4b))

## [9.5.1](https://github.com/panva/node-oidc-provider/compare/v9.5.0...v9.5.1) (2025-08-29)


### Fixes

* safeguard global navigator access ([1caae21](https://github.com/panva/node-oidc-provider/commit/1caae21008fb69eb3933354a705886c751876cdb))

## [9.5.0](https://github.com/panva/node-oidc-provider/compare/v9.4.2...v9.5.0) (2025-08-29)


### Features

* support ML-DSA JWS algorithm identifiers ([f308b09](https://github.com/panva/node-oidc-provider/commit/f308b0930c665058c64b713438bf956c7af2449c))


### Refactor

* add a warning for more unsupported runtimes ([c55d58e](https://github.com/panva/node-oidc-provider/commit/c55d58e8d56b56ecd724a10e133933a955593879))
* make warn/info warnings colorization a no-op in nonTTY ([0c0a5b6](https://github.com/panva/node-oidc-provider/commit/0c0a5b633ddac7d9d98b485a69608f9e947ebdef))

## [9.4.2](https://github.com/panva/node-oidc-provider/compare/v9.4.1...v9.4.2) (2025-08-23)


### Fixes

* check for native logout redirect allowed same way as during auth ([419f286](https://github.com/panva/node-oidc-provider/commit/419f286529fd66d0cb577ea64dd544867eb27b18)), closes [#1351](https://github.com/panva/node-oidc-provider/issues/1351)

## [9.4.1](https://github.com/panva/node-oidc-provider/compare/v9.4.0...v9.4.1) (2025-08-11)


### Documentation

* add an getAttestationSignaturePublicKey example ([3a7730c](https://github.com/panva/node-oidc-provider/commit/3a7730c451ac242122bf0105732c24fbfa460bef))


### Refactor

* avoid code generation from strings by pre-compiling eta views ([f997073](https://github.com/panva/node-oidc-provider/commit/f997073f09e8c699ff4319ef0fbf19167347e3a7))
* drop the default implementation of pairwiseIdentifier ([6a2338a](https://github.com/panva/node-oidc-provider/commit/6a2338a76bc87b31b4b9854dcbf61bf5fce4af68))
* remove oidc-token-hash dependency ([b607491](https://github.com/panva/node-oidc-provider/commit/b607491d1c9dc20c8884b6ac7fbd0286845c616a))

## [9.4.0](https://github.com/panva/node-oidc-provider/compare/v9.3.0...v9.4.0) (2025-07-17)


### Features

* Experimental support for Attestation-Based Client Authentication ([d655ebd](https://github.com/panva/node-oidc-provider/commit/d655ebde6428d5b8a5d2f29ce2fc2a0203f442d7))


### Refactor

* consistently lowercase header names and use req/res aliases ([1748a54](https://github.com/panva/node-oidc-provider/commit/1748a54e8212d2c716977e0ea3c2c01f68117261))
* **cors:** update default client-based cors helper ([77e06eb](https://github.com/panva/node-oidc-provider/commit/77e06eb554a4a62a87a350b348ae2d22a4d8548c))
* reconcile dpop and attestation challenge implementations ([e31f639](https://github.com/panva/node-oidc-provider/commit/e31f63977c0ffdce620301f23d8af0c93fb52b71))


### Documentation

* updated documentation for configuration options ([5710d61](https://github.com/panva/node-oidc-provider/commit/5710d619ce684b2974433949e9115f450820f8f5))

## [9.3.0](https://github.com/panva/node-oidc-provider/compare/v9.2.0...v9.3.0) (2025-07-16)


### Features

* **revocation:** add an allowed token revocation policy helper ([a7e47e4](https://github.com/panva/node-oidc-provider/commit/a7e47e4cc700722ed826c2a86a3aabb4fd1846ee))


### Documentation

* update README.md ([857c34d](https://github.com/panva/node-oidc-provider/commit/857c34d2c9816af309933f2eb4d6fcb84306d167))


### Fixes

* **introspection:** use unsupported_token_type to indicate structured jwt tokens cannot be introspected ([c9001be](https://github.com/panva/node-oidc-provider/commit/c9001be07d8f5a0ff32efcc61f5bdfec7bdda3fb))
* **revocation:** use unsupported_token_type to indicate structured jwt tokens cannot be revoked ([b45b00c](https://github.com/panva/node-oidc-provider/commit/b45b00caad804894f225ddffcaaf84226172ae43))


### Refactor

* pull structured token rejection to a shared middleware ([30367af](https://github.com/panva/node-oidc-provider/commit/30367af7ea6a5a399785d8fd78f7a499d4f7ae48))

## [9.2.0](https://github.com/panva/node-oidc-provider/compare/v9.1.3...v9.2.0) (2025-06-24)


### Features

* expose RFC8414 Authorization Server Metadata route ([c5bd90f](https://github.com/panva/node-oidc-provider/commit/c5bd90f2021e7614115873202482b46e36388b39))

## [9.1.3](https://github.com/panva/node-oidc-provider/compare/v9.1.2...v9.1.3) (2025-06-02)


### Fixes

* ensure an account's accountId and claims().sub is the same ([9b89153](https://github.com/panva/node-oidc-provider/commit/9b89153c0ea2f2280a26e35f3b66d1900aed7c79)), closes [#1336](https://github.com/panva/node-oidc-provider/issues/1336)

## [9.1.2](https://github.com/panva/node-oidc-provider/compare/v9.1.1...v9.1.2) (2025-05-28)


### Fixes

* ignore allowOmittingSingleRegisteredRedirectUri when FAPI 2.0 is used ([e2de529](https://github.com/panva/node-oidc-provider/commit/e2de529bea57e9349bed54bda7f42f2e20ba8602))

## [9.1.1](https://github.com/panva/node-oidc-provider/compare/v9.1.0...v9.1.1) (2025-04-28)


### Refactor

* oidc-provider now uses koa@3 ([3a83d32](https://github.com/panva/node-oidc-provider/commit/3a83d324f611e8f42e79f92f6f046721dcc5dba2))

## [9.1.0](https://github.com/panva/node-oidc-provider/compare/v9.0.1...v9.1.0) (2025-04-26)


### Features

* experimental support for OIDC RP Metadata Choices ([f3550da](https://github.com/panva/node-oidc-provider/commit/f3550daff76329a5a820a85a40afebcd0638abb6))


### Fixes

* only include DPoP-Nonce in Access-Control-Expose-Headers when DPoP is enabled ([e769aa8](https://github.com/panva/node-oidc-provider/commit/e769aa85f07f48d4970aad2500e62a3042659d3c))


### Refactor

* avoid assignment operators in conditional expressions ([b7ed877](https://github.com/panva/node-oidc-provider/commit/b7ed877a5d75d1eabfefd1034d74b89c1925470a))
* improve static find performance ([106f94a](https://github.com/panva/node-oidc-provider/commit/106f94a11f36e0ae3058b8d457ab25a82b3bc742))
* update some default helpers for readability ([0818c36](https://github.com/panva/node-oidc-provider/commit/0818c36fc4d2004d05b3e011873d02be307de478))


### Documentation

* more clarity for features.dPoP.allowReplay ([779a141](https://github.com/panva/node-oidc-provider/commit/779a14187d22218ea770dee255d32c2fb6c25564))

## [9.0.1](https://github.com/panva/node-oidc-provider/compare/v9.0.0...v9.0.1) (2025-04-17)


### Documentation

* mark experimental features more distinctly ([986adc5](https://github.com/panva/node-oidc-provider/commit/986adc5904841bae45e50f9aec486986534d36a0))
* update references and styling of spec links ([a4787b8](https://github.com/panva/node-oidc-provider/commit/a4787b87084dd90c94043cfabfaa317fc3c4021c))


### Fixes

* DCR endpoints only include www-authenticate for non-registration related errors ([9a864d6](https://github.com/panva/node-oidc-provider/commit/9a864d6e1af242ceb6456f2473a1925c112367b5))


### Refactor

* client schema defaults and static props ([843943d](https://github.com/panva/node-oidc-provider/commit/843943d871d05445e6af2dc8fcd636f73a2751a6))
* handle frame-ancestors in wmrm without a regexp ([4f85585](https://github.com/panva/node-oidc-provider/commit/4f8558525f0e8025abdaa38c29eff23085694775))
* push multiple elements to the recognized array in client_schema ([d478a8b](https://github.com/panva/node-oidc-provider/commit/d478a8bd8a3ab539cde5d695ef8a3f06c63e7778))
* simpler DCR validate registration access token ([5f01eda](https://github.com/panva/node-oidc-provider/commit/5f01edadb81e7a9b739f65c31b738f41a7a6898e))

## [9.0.0](https://github.com/panva/node-oidc-provider/compare/v8.8.1...v9.0.0) (2025-04-15)


### ⚠ BREAKING CHANGES

* authorization and logout endpoints no longer support the HTTP POST method by default, this can be re-enabled using the `enableHttpPostMethods` boolean configuration, this also requires that cookies.long.sameSite is set to `none`
* cookie session sameSite attribute default is now "lax" instead of "none"
* userinfo requests with bearer tokens will now fail if they also include DPoP
* userinfo now includes both dpop and bearer challenges when dpop is enabled
* accessing protected resources without an access token will now yield a 401 HTTP Status Code instead of a 400
* default PKCE configuration no longer requires PKCE to be used unless RFC9700 or a given profile says so
* removed the provider.Account getter
* all Provider routes will now end the HTTP request when finished, koa middlewares that are "downstream" will no longer be executed after a route is matched in oidc-provider, "upstream" control flows are unaffected
* the Provider no longer includes a catch-all 404 Not Found error handler
* FAPI profile behaviours no longer force PKCE, these should be forced by configuring the pkce.required configuration helper the default of which already does so.
* the server's JWK Key IDs (JWK kid parameter) now must be unique, no two keys must use the same kid.
* the revokeGrantPolicy configuration helper is now also invoked during opaque Access Token revocation, its default return remains false for this case though
* CIBA ping and poll delivery mode ID Tokens no longer include at_hash, urn:openid:params:jwt:claim:rt_hash, and urn:openid:params:jwt:claim:auth_req_id
* authorization code grant type issued ID Tokens no longer include at_hash
* device authorization grant type issued ID Tokens no longer include at_hash
* refresh token grant type issued ID Tokens no longer include at_hash
* implicit grant type issued ID Tokens no longer include s_hash unless the request is a FAPI 1.0 Final request
* global fetch() API is now used to make outgoing HTTP requests instead of the "got" module.
* the httpOptions configuration option was removed and a new option to accomodate the use of fetch() interface was added. This options is aptly called "fetch" and its call signature and expected returns mirror the fetch() API.
* Enabling JAR (Request Objects by Value) is now enabled via features.requestObjects.enabled boolean instead of features.requestObjects.request boolean
* removed support for Passing a Request Object by Reference (JAR request_uri)
* removed legacy sameSite cookie fallback
* removed support for Node.js 18.x
* removed support for Node.js 20.x
* removed the pkce.methods configuration
* removed the features.requestObjects.mode configuration
* removed support for Ed448
* removed support for X448
* removed support for secp256k1 / ES256K
* removed support for FAPI 1.0 ID2

### Features

* Access Token revocation may now also optionally revoke the underlying grant ([4f69668](https://github.com/panva/node-oidc-provider/commit/4f696680ba86f5589e74405a9381c90b87344d64))
* add support for the fully-specified Ed25519 JWS Algorithm Identifier ([645b900](https://github.com/panva/node-oidc-provider/commit/645b900aa4e07d314d723b9484f132c95e002ee2))
* DPoP support is now enabled by default ([a5694af](https://github.com/panva/node-oidc-provider/commit/a5694af25989f5cb9612bf4c9322fb51c5abb984))
* Experimental support for external signing keys, e.g. in a KMS or HSM ([8b3ceff](https://github.com/panva/node-oidc-provider/commit/8b3ceff0206cf6367d92a9151c6a4ce570778f49))
* expose current requests' ctx via Provider.ctx static getter ([1fbd81b](https://github.com/panva/node-oidc-provider/commit/1fbd81b9a2a1c064f0e56ae15717f12e6900c8af))
* update FAPI 2.0 implementation to FAPI 2.0 Final ([eff3115](https://github.com/panva/node-oidc-provider/commit/eff31151ae6721db7b0ea9ae72111f5d425dd302))


### Documentation

* auto-format code blocks ([c2c520f](https://github.com/panva/node-oidc-provider/commit/c2c520fe294c907a85b06d0498481b73faa5307c))
* dpop cannot acked anymore, it is stable ([a48c51f](https://github.com/panva/node-oidc-provider/commit/a48c51f1129624ac7d5fc1d43eb860ee2d7fa85a))
* improvements to linked resources ([cf77770](https://github.com/panva/node-oidc-provider/commit/cf777703517f903d053d446b2118048f69c771d5))
* mention external types ([5f8a450](https://github.com/panva/node-oidc-provider/commit/5f8a450ab9546f6ab1d40eec840d15336b5fb138))
* move adapters to the Community Guides Discussions section ([ba806ca](https://github.com/panva/node-oidc-provider/commit/ba806ca86908f7d53a6b1207038889c9ef43cef0))
* move recipes to the Community Guides Discussions section ([cd8da28](https://github.com/panva/node-oidc-provider/commit/cd8da28c7631e2fe6a302f7a2c407d843d2dee22))
* remove mentions of the connect server framework ([7cb1aaa](https://github.com/panva/node-oidc-provider/commit/7cb1aaab23800a26e36f40025936ca0f0d98660f))
* update README to use named exports ([8355886](https://github.com/panva/node-oidc-provider/commit/8355886459b756a648b481321c048a6e0af5ca71))
* update version support matrix ([abbfe2f](https://github.com/panva/node-oidc-provider/commit/abbfe2f3f2407d35c627a4800703808c6dfb0686))


### Fixes

* no access token provided error is now a 401 ([8493e2d](https://github.com/panva/node-oidc-provider/commit/8493e2dfee3546b9a7a4c75ef59e5937ad747946))
* userinfo now includes both dpop and bearer challenges when dpop is enabled ([1093f6b](https://github.com/panva/node-oidc-provider/commit/1093f6b0ab7da26cc00d715f5cfcbb4641b8c874))


### Refactor

* change default PKCE usage requirement ([fdf8ad8](https://github.com/panva/node-oidc-provider/commit/fdf8ad87922cdf670c2235cafba5c49fb7d7ab3e))
* change default session cookie from sameSite none to lax ([b47eee8](https://github.com/panva/node-oidc-provider/commit/b47eee8175125c20937cccaab75b613b03f9ecb1))
* cleanup unused azp claim code ([6c57e63](https://github.com/panva/node-oidc-provider/commit/6c57e634b2b5afb15712d882a0a6e1132dd77802))
* deprecate the `.app` getter ([9b61212](https://github.com/panva/node-oidc-provider/commit/9b61212c630b00ff802a62f62b2e26d87d90caa2))
* disable HTTP POST Method handling of authorization and logout endpoints ([d56304c](https://github.com/panva/node-oidc-provider/commit/d56304c79ce95609c0040325aeb0f8dde490707d))
* encryption and key derivation is not blocking the main thread ([73a422f](https://github.com/panva/node-oidc-provider/commit/73a422fdd3c4b5ea134b7aabbf2f49bbe82cea0a))
* ensure all route handlers are final ([8cc44e6](https://github.com/panva/node-oidc-provider/commit/8cc44e6b41c69f8a810cebc95829e565584c833c))
* escape www-authenticate backslashes despite not directly using them ([e789b98](https://github.com/panva/node-oidc-provider/commit/e789b988c12857254e640af54b27b4241363396c))
* increase all random identifiers from ~126 bits of randomness to ~256 ([45721f8](https://github.com/panva/node-oidc-provider/commit/45721f8fa05a3ae3990e2f025aabebe787e61f81))
* minimal change to support koa@3 ([925cee5](https://github.com/panva/node-oidc-provider/commit/925cee57db319d8d63fe192f09bfc26b9171a334))
* no more warnings if cookie keys are missing ([7ab6157](https://github.com/panva/node-oidc-provider/commit/7ab615730b7d236e5e53d2948305989b88ae7a1d))
* omit generic "typ: JWT" in issued JSON Web Tokens ([4eb4004](https://github.com/panva/node-oidc-provider/commit/4eb4004ab66d75eb8627fe6b935fa51f6bbfb80e))
* pass over internal configuration getters ([0243964](https://github.com/panva/node-oidc-provider/commit/0243964c369bd0e444b83138d1c83b530febea0b))
* Provider is now the Koa application instance ([167216e](https://github.com/panva/node-oidc-provider/commit/167216ed916492c141962510c18474c8327e9b70))
* remove hardcoded require PKCE checks ([be0b2fd](https://github.com/panva/node-oidc-provider/commit/be0b2fd0aaa0f22c18ef9e277fc760e99ae1b675))
* remove object-hash dependency ([fda9385](https://github.com/panva/node-oidc-provider/commit/fda9385e125645dc49e4a2a9c15a6007c314eecb))
* remove optional ID Token _hash claims ([58ca2c2](https://github.com/panva/node-oidc-provider/commit/58ca2c267d867d1dc6c05375278156ba90987a6f))
* remove the provider.Account getter ([dd2bde4](https://github.com/panva/node-oidc-provider/commit/dd2bde4e8256204a24a606c8dacd61d0801cb0ed))
* remove unused code ([e5fc3cb](https://github.com/panva/node-oidc-provider/commit/e5fc3cbbcc2f95dd141eca899e60938782aa78e7))
* remove uses of randomFill and Buffer.allocUnsafe ([00fe106](https://github.com/panva/node-oidc-provider/commit/00fe106b8c40d6c2acc2dd5bebaaf8873150c41a))
* removed legacy sameSite cookie fallback ([2defa70](https://github.com/panva/node-oidc-provider/commit/2defa709b53d3cec15f4b1c985aa000858c1c6e6))
* removed support for FAPI 1.0 ID2 ([311e3e2](https://github.com/panva/node-oidc-provider/commit/311e3e25e2b9e3e41ff01a703dac9a3ee42e90a8))
* removed support for Passing a Request Object by Reference (JAR request_uri) ([bacf375](https://github.com/panva/node-oidc-provider/commit/bacf375caa2bbdd153424f704c3475324290aca7))
* removed the features.requestObjects.mode configuration ([4ec8327](https://github.com/panva/node-oidc-provider/commit/4ec8327c0b7186e1edad6c2960417537fedb6dc7))
* removed the pkce.methods configuration ([4a736b8](https://github.com/panva/node-oidc-provider/commit/4a736b82f2963fdb4545142d14345c547c8ceb15))
* Request Object (JAR) is now enabled with features.requestObjects.enabled ([20d60a4](https://github.com/panva/node-oidc-provider/commit/20d60a49e584cf6edcd7818322b157e677d8992d))
* simplify default assertJwtClaimsAndHeader configuration ([1ea27a6](https://github.com/panva/node-oidc-provider/commit/1ea27a6358709c4805011237f124a43e5179c8ca))
* update Node.js support matrix ([db57556](https://github.com/panva/node-oidc-provider/commit/db575566c2648dc0dbd03344e6ad9c4cbf36d720))
* use fetch() api to make outgoing HTTP requests ([cc70e5a](https://github.com/panva/node-oidc-provider/commit/cc70e5aaf005cfb3ef8bde1c945d96ec16d5b8fb))
* use hkdf in dpop's rolling nonce calculation ([7b77967](https://github.com/panva/node-oidc-provider/commit/7b77967edf2ace72abe41070aa19bd6b8d211b8c))
* use more optional chaining ([e5539ae](https://github.com/panva/node-oidc-provider/commit/e5539aed3ac32b9177723b0448aa3288f877dff0))
* use oneshot hash methods instead of intermediate Hash objects ([2dc4bd1](https://github.com/panva/node-oidc-provider/commit/2dc4bd1f3ea43c24f69ff7210e4e8f4341c08124))
* use structuredClone instead of JSON.stringify then parse ([ad02170](https://github.com/panva/node-oidc-provider/commit/ad021700dcfc41fe3152b59e6cf06dfb65529ab5))
* use URL.parse ([11e1b33](https://github.com/panva/node-oidc-provider/commit/11e1b330c8df82c566c68897815f9af4a3b688b7))
* userinfo requests with bearer tokens will now fail if they also include DPoP ([e5efa5c](https://github.com/panva/node-oidc-provider/commit/e5efa5cfdab7ba931a917d75b91a1428ad0b0cdb))

## [8.8.1](https://github.com/panva/node-oidc-provider/compare/v8.8.0...v8.8.1) (2025-03-06)


### Fixes

* add "exp" to Logout Tokens ([c6c01f1](https://github.com/panva/node-oidc-provider/commit/c6c01f112c29ade904a23d90bc3ea74408981bba)), closes [#1295](https://github.com/panva/node-oidc-provider/issues/1295)


### Documentation

* update spec links ([076ee58](https://github.com/panva/node-oidc-provider/commit/076ee58b3df60e1987a0f4a06fb8c42ea75e68ba))

## [8.8.0](https://github.com/panva/node-oidc-provider/compare/v8.7.0...v8.8.0) (2025-02-17)


### Features

* mark RFC9701 (features.jwtIntrospection) as stable ([e2a2de2](https://github.com/panva/node-oidc-provider/commit/e2a2de2c9e51095b1a856b57af640f3b95cf6be9))

## [8.7.0](https://github.com/panva/node-oidc-provider/compare/v8.6.1...v8.7.0) (2025-02-13)


### Features

* allow own KeyGrip instances in cookies.keys configuration ([d5d2900](https://github.com/panva/node-oidc-provider/commit/d5d2900b2a7224e19d79a43b59d8888ad3bfbbf3))

## [8.6.1](https://github.com/panva/node-oidc-provider/compare/v8.6.0...v8.6.1) (2025-01-19)


### Fixes

* allow specifying the user-agent header for outgoing requests ([#1287](https://github.com/panva/node-oidc-provider/issues/1287)) ([c77513c](https://github.com/panva/node-oidc-provider/commit/c77513ca44115661f96fb2ae200c194966d76aca))

## [8.6.0](https://github.com/panva/node-oidc-provider/compare/v8.5.3...v8.6.0) (2024-11-21)


### Features

* add a helper for asserting JWT Client Auth claims and header ([82d4e50](https://github.com/panva/node-oidc-provider/commit/82d4e506c8d2dd807c4a0211770dc172f541ba2a))


### Documentation

* update verbiage "provider" > "authorization server" ([3768192](https://github.com/panva/node-oidc-provider/commit/3768192b811452c046e5e3f8b5bc43f6e041c2ec))


### Refactor

* move assertJwtClaimsAndHeader after regular JWT claims set validation ([05f6bf4](https://github.com/panva/node-oidc-provider/commit/05f6bf489b66bd35d8be80cdad64605ef33a7dfc))

## [8.5.3](https://github.com/panva/node-oidc-provider/compare/v8.5.2...v8.5.3) (2024-11-05)


### Fixes

* normalize single string set-cookie headers ([6effeed](https://github.com/panva/node-oidc-provider/commit/6effeed4629e1dc229e00d93cdec45b8cf4d015e))

## [8.5.2](https://github.com/panva/node-oidc-provider/compare/v8.5.1...v8.5.2) (2024-10-19)


### Refactor

* remove use of node:url in favour of WHATWG URL ([0dc59a1](https://github.com/panva/node-oidc-provider/commit/0dc59a142df3d1cbe72e41b7d8a8abd03c2f0ffd))


### Documentation

* update docs/README.md ([07f6333](https://github.com/panva/node-oidc-provider/commit/07f6333cca19f8cf65db56e84172885910eda8db))

## [8.5.1](https://github.com/panva/node-oidc-provider/compare/v8.5.0...v8.5.1) (2024-07-03)


### Documentation

* update README.md ([41a7a0b](https://github.com/panva/node-oidc-provider/commit/41a7a0b857cf3428da240884af305774484f39a2))


### Refactor

* **build:** export Provider also as a named export ([083c7c4](https://github.com/panva/node-oidc-provider/commit/083c7c4cc6350ed99fe9aaee69d316cdd2d0f906))

## [8.5.0](https://github.com/panva/node-oidc-provider/compare/v8.4.7...v8.5.0) (2024-06-28)


### Features

* add a Client static validate() method ([d1f7d73](https://github.com/panva/node-oidc-provider/commit/d1f7d736b57b8167374a22d7f88bf181b58ff9c6))
* add a helper allowing custom claims parameter validations ([ec2a1f5](https://github.com/panva/node-oidc-provider/commit/ec2a1f5a32f48758cea09d08303e895a08aa53d6))
* add experimental support for RFC9396 - Rich Authorization Requests ([e9fb573](https://github.com/panva/node-oidc-provider/commit/e9fb5735c2e2410afed035b3b9046eb53371e1b1))
* add response_modes client metadata allow list ([76f9af0](https://github.com/panva/node-oidc-provider/commit/76f9af086ebffaa50e6cc4f9ccdb2c25ac307444))
* allow extraParams to define validations for extra parameters ([b7d3322](https://github.com/panva/node-oidc-provider/commit/b7d3322ff8be2a106d6477d490129327ef7bd2ca))
* **DPoP:** add a setting to disable DPoP Proof Replay Detection ([2744fc8](https://github.com/panva/node-oidc-provider/commit/2744fc8c093ac3c9d43720f243c89ea682b7eee6))
* **DPoP:** send a dpop-nonce when the proof's iat check fails and nonces are configured but not required ([1b073c0](https://github.com/panva/node-oidc-provider/commit/1b073c021f5414bd4835f4e0fe01341a8f52aa35))
* **FAPI:** add FAPI 2.0 profile behaviours ([5212609](https://github.com/panva/node-oidc-provider/commit/5212609832167ecd9de29094a89f418522bcbef3))
* **JAR:** add a helper allowing custom JWT claim and header validations ([be9242a](https://github.com/panva/node-oidc-provider/commit/be9242a74d46fb4b6deeb5ec2da112bc9563149e))
* **PAR:** add a setting to allow use of unregistered redirect_uri values ([a7e73fa](https://github.com/panva/node-oidc-provider/commit/a7e73fa5db6893c37a2cd77f83da8b4edaf9cefc))
* update Web Message Response Mode and remove its Relay Mode ([a91add8](https://github.com/panva/node-oidc-provider/commit/a91add87f54dfd4f57faa5cd1292a02fa5e32b30))


### Fixes

* **DPoP,mTLS:** reject client configuration in which binding is required but response types include an implicit token response ([cd7e0f4](https://github.com/panva/node-oidc-provider/commit/cd7e0f4a8e7b847ab3ada8af7a4ffaecfcdcfe0f))


### Refactor

* deprecate FAPI 1.0 ID2, lax request objects, plain PKCE ([3e8a784](https://github.com/panva/node-oidc-provider/commit/3e8a7844fd0060839a5617cccbc40ec75d38f480))
* don't use overwrite cookie option by default ([dfbcb94](https://github.com/panva/node-oidc-provider/commit/dfbcb94cfdb5a48b10e308574a7e012ca5cce54c))
* **DPoP:** move the accepted timespan into a constant ([a8e8006](https://github.com/panva/node-oidc-provider/commit/a8e8006e10e02b6b20b8e5cde2361e1290da1162))
* **DPoP:** omit sending the dpop-nonce header if the existing one used is fresh ([4d635e2](https://github.com/panva/node-oidc-provider/commit/4d635e2b6c12ea373c037514820d0bed4af57495))
* ensure param-assigned max_age from client.defaultMaxAge is a string ([0c52469](https://github.com/panva/node-oidc-provider/commit/0c52469f08b0a4a1854d90a96546a3f7aa090e5e))
* **FAPI:** deprecate FAPI profile hardcoded PKCE checks ([56641ec](https://github.com/panva/node-oidc-provider/commit/56641ecf5d9a49061a229a1b10deaa314a2ffcd8))
* **JAR:** authorization requests with JAR now require a client_id parameter ([9131cd5](https://github.com/panva/node-oidc-provider/commit/9131cd56148aebfaec08a497f2a50d37baafd001))
* **JAR:** Request Objects are no longer checked for one time use ([18efa70](https://github.com/panva/node-oidc-provider/commit/18efa7083fb4abde4e48f2930f728f20e94a258e))
* **PAR:** consume PAR after user interactions instead of before ([53babe6](https://github.com/panva/node-oidc-provider/commit/53babe6dca1eeba70ef3e2c2ffee4121e3418d1e))
* store claims value parsed in non-JAR PAR ([9cd865b](https://github.com/panva/node-oidc-provider/commit/9cd865b726c8db39c5c1e480e2a717e589f37b5a))
* use invalid_request instead of unauthorized_client ([7947d87](https://github.com/panva/node-oidc-provider/commit/7947d87206dbf3b9b1d5cce1946066fc9bc2b896))

## [8.4.7](https://github.com/panva/node-oidc-provider/compare/v8.4.6...v8.4.7) (2024-06-20)


### Fixes

* include ID Token auth_time when client's default_max_age is zero ([bebda04](https://github.com/panva/node-oidc-provider/commit/bebda04fd125a69829fa933aa0bf4c7bb22f601e))

## [8.4.6](https://github.com/panva/node-oidc-provider/compare/v8.4.5...v8.4.6) (2024-04-23)


### Documentation

* adds events and debugging recipe ([#1246](https://github.com/panva/node-oidc-provider/issues/1246)) ([0bf7696](https://github.com/panva/node-oidc-provider/commit/0bf769665263117420026d877d889a76ce674a4b))
* fix client_secret_basic special characters encoding example ([73baae1](https://github.com/panva/node-oidc-provider/commit/73baae15001a30b8c29c3c35ea2b821a7fb3eafd))
* re-run update docs ([99cc84a](https://github.com/panva/node-oidc-provider/commit/99cc84ac64c9455a11c72f403ab4783bd222c5a5))


### Refactor

* avoid iteration resource iteration in client_credentials ([e306640](https://github.com/panva/node-oidc-provider/commit/e30664025d6d0acd86ba05f09e02b7880af11765))
* avoid use of prototype attributes in object-hash ([270af1d](https://github.com/panva/node-oidc-provider/commit/270af1da83dda4c49edb4aaab48908f737d73379))
* use logical or assignment ([8f55588](https://github.com/panva/node-oidc-provider/commit/8f55588a1a51aafba95c22aee05c7a0beb55e063))


### Fixes

* ensure each individual resource indicator is a valid URI ([d9e1ad2](https://github.com/panva/node-oidc-provider/commit/d9e1ad21dff34b2619664475728548178ca5e2f8))

## [8.4.5](https://github.com/panva/node-oidc-provider/compare/v8.4.4...v8.4.5) (2024-01-17)


### Refactor

* use doc argument in web_message js code ([da3198b](https://github.com/panva/node-oidc-provider/commit/da3198b307ea50ff3033d9b5eaa873025494a20e))


### Fixes

* add missing opening html tags ([23997c5](https://github.com/panva/node-oidc-provider/commit/23997c5946c14a301868dabbbe43431227234adb))
* **DPoP:** mark defaulted dpop_jkt parameter as trusted ([ee633f3](https://github.com/panva/node-oidc-provider/commit/ee633f3baa2308ec84cd02d93db737a17baf37bb))

## [8.4.4](https://github.com/panva/node-oidc-provider/compare/v8.4.3...v8.4.4) (2024-01-08)


### Refactor

* test decoded basic auth tokens for their VSCHAR pattern ([3f86cc0](https://github.com/panva/node-oidc-provider/commit/3f86cc097768d83b1a4d734d0f7a7244676572b4))


### Fixes

* **DPoP,PAR,JAR:** validate DPoP before invalidating JAR during PAR ([ca0f999](https://github.com/panva/node-oidc-provider/commit/ca0f999e82ab7048b3f22a9d7798d17c7aafa405))

## [8.4.3](https://github.com/panva/node-oidc-provider/compare/v8.4.2...v8.4.3) (2023-12-14)

## [8.4.2](https://github.com/panva/node-oidc-provider/compare/v8.4.1...v8.4.2) (2023-12-02)


### Fixes

* reject client JSON Web Key Set `null` value ([#1237](https://github.com/panva/node-oidc-provider/issues/1237)) ([cce6d43](https://github.com/panva/node-oidc-provider/commit/cce6d43535da72cd244b18d8a42a8dbee5f0f955))

## [8.4.1](https://github.com/panva/node-oidc-provider/compare/v8.4.0...v8.4.1) (2023-10-25)

## [8.4.0](https://github.com/panva/node-oidc-provider/compare/v8.3.2...v8.4.0) (2023-09-08)


### Features

* **DPoP:** remove experimental flag, DPoP is now RFC9449 ([89d133e](https://github.com/panva/node-oidc-provider/commit/89d133edf5090e017ef353a00ecaf578fee2f178))

## [8.3.2](https://github.com/panva/node-oidc-provider/compare/v8.3.1...v8.3.2) (2023-09-02)


### Fixes

* assign extraTokenClaims return to the model ([e296dc7](https://github.com/panva/node-oidc-provider/commit/e296dc78247bf9259f088a9b5400cf9d921b23cf))

## [8.3.1](https://github.com/panva/node-oidc-provider/compare/v8.3.0...v8.3.1) (2023-08-30)


### Fixes

* **DPoP:** compare htu scheme and hostname case independent ([b72d668](https://github.com/panva/node-oidc-provider/commit/b72d6686489bdb1a7484e1ba697614137cd36b73))

## [8.3.0](https://github.com/panva/node-oidc-provider/compare/v8.2.2...v8.3.0) (2023-08-27)


### Features

* allow specifying the user-agent header for outgoing requests ([95f24ef](https://github.com/panva/node-oidc-provider/commit/95f24ef6365ae54375f7459cec19fb1c6b8ba291))

## [8.2.2](https://github.com/panva/node-oidc-provider/compare/v8.2.1...v8.2.2) (2023-05-30)


### Fixes

* ignore non-existent resource scopes during refresh ([#1222](https://github.com/panva/node-oidc-provider/issues/1222)) ([bdf23ba](https://github.com/panva/node-oidc-provider/commit/bdf23baf7ac58d629390344d93fc29224c67331e))

## [8.2.1](https://github.com/panva/node-oidc-provider/compare/v8.2.0...v8.2.1) (2023-05-06)


### Fixes

* ignore post_logout_redirect_uris when logout is disabled ([#1221](https://github.com/panva/node-oidc-provider/issues/1221)) ([d7dd6cf](https://github.com/panva/node-oidc-provider/commit/d7dd6cf13739dea62b6e72531ba27ef27fbf4e50))

## [8.2.0](https://github.com/panva/node-oidc-provider/compare/v8.1.2...v8.2.0) (2023-04-24)


### Features

* add correlation identifier to interactions ([#1218](https://github.com/panva/node-oidc-provider/issues/1218)) ([c072352](https://github.com/panva/node-oidc-provider/commit/c072352e586cc161d51513408ae5fd063d9867d1))

## [8.1.2](https://github.com/panva/node-oidc-provider/compare/v8.1.1...v8.1.2) (2023-04-21)

## [8.1.1](https://github.com/panva/node-oidc-provider/compare/v8.1.0...v8.1.1) (2023-03-09)

## [8.1.0](https://github.com/panva/node-oidc-provider/compare/v8.0.0...v8.1.0) (2023-01-23)


### Features

* mTLS.getCertificate helper can return a X509Certificate object ([be3f47f](https://github.com/panva/node-oidc-provider/commit/be3f47f686ee3bb2bdde2f8a1f77f1c619457a3b))

## [8.0.0](https://github.com/panva/node-oidc-provider/compare/v7.14.3...v8.0.0) (2022-12-03)


### ⚠ BREAKING CHANGES

* Default clock skew tolerance is now set to 15 seconds (previously 0 seconds tolerance). This can be reverted using the `clockTolerance` configuration option.
* The userinfo endpoint will no longer echo back `x-fapi-interaction-id` headers. This can be reverted using a custom pre-middleware.
* `request_uri` parameter is no longer supported at the Device Authorization Endpoint.
* The combination of FAPI and CIBA features no longer forces CIBA clients to use JAR. To continue conforming to a given FAPI CIBA profile that requires the use of JAR either set `features.requestObjects.requireSignedRequestObject` to `true` as a global policy or set `require_signed_request_object` or `backchannel_authentication_request_signing_alg` client metadata.
* PAR no longer automatically enables the support for JAR. To support PAR with JAR configure both `features.pushedAuthorizationRequests` and `features.requestObjects.request`.
* CIBA no longer automatically enables the support for JAR. To support CIBA with JAR configure both `features.ciba` and `features.requestObjects.request`.
* Pushed Authorization Requests (PAR) are now enabled by default. This can be reverted using the `features.pushedAuthorizationRequests.enabled` configuration option.
* Completely removed v6.x way of setting access token formats.
* `expiresWithSession()` for access tokens issued by the authorization endpoint will now only be invoked for opaque format access tokens.
* Default allowed DPoP signing algorithms are now just ES256 and EdDSA. RSA algorithms not allowed by default. This can be reverted using the `enabledJWA.dPoPSigningAlgValues` configuration option.
* Omitting a redirect_uri parameter when a single one is registered is now enabled by default (again). This can be reverted using the `allowOmittingSingleRegisteredRedirectUri` configuration option.
* `features.fapi.profile` is now a required configuration option when `features.fapi.enabled` is `true`.
* `id_token_signed_response_alg` now must be set when `id_token_encrypted_response_alg` is also set on a client.
* `userinfo_signed_response_alg` now must be set when `userinfo_encrypted_response_alg` is also set on a client.
* `introspection_signed_response_alg` now must be set when `introspection_encrypted_response_alg` is also set on a client.
* `authorization_signed_response_alg` now must be set when `authorization_encrypted_response_alg` is also set on a client.
* The RSA1_5 JWE Key Management Algorithm, which was previously disabled by default, is now completely removed.
* `request_uri` parameter support is now disabled by default. This can be reverted using the `features.requestObjects.requestUri` configuration option.
* `httpOptions` return property `lookup` was renamed to `dnsLookup`.
* `httpOptions` return property `timeout` was removed, return an `AbortSignal` instance as `signal` property instead.
* `oidc-provider` is now an ESM-only module, it must now be imported using the `import` declaration or the `import()` syntax, the `Provider` constructor is the module's default export, the `errors` and `interactionPolicy` exports are the package's named exports. There is no `Provider` named export.
* `httpOptions` no longer defaults to using the npm module `cacheable-lookup` as its `dnsLookup` option. It defaults to `node:dns` module's `lookup` export instead.
* PASETO Access Token format support was removed.
* Removed support for Node.js 12.
* Removed support for Node.js 14.
* Removed support for Node.js 16.
* Node.js LTS 18 (^18.12.0) is now required.
* Default Authorization Code duration is now 60 seconds instead of 10 minutes. This can be reverted using the `ttl.AuthorizationCode` configuration option.
* Request Object use now defaults to its stricter definition from RFC 9101 rather than OIDC Core 1.0. This can be reverted using the `features.requestObjects.mode` configuration option.
* The "none" JWS algorithm, which was previously disabled by default, is now completely removed.
* The PBKDF2 based JWE Key Management Algorithms, which were previously disabled by default, are now completely removed.
* The client registration management update action now rotates registration access tokens by default. This can be reverted using the `features.registrationManagement.rotateRegistrationAccessToken` configuration option.
* It is no longer possible to pass Bearer tokens using the `access_token` query string parameter. This can be reverted using the `acceptQueryParamAccessTokens` configuration option.
* The `tokenEndpointAuthMethods` configuration method was renamed to `clientAuthMethods`.
* The `enabledJWA.tokenEndpointAuthSigningAlgValues` configuration method was renamed to `enabledJWA.clientAuthSigningAlgValues`.
* The non-standard `introspection_endpoint_auth_method`, and `introspection_endpoint_auth_signing_alg` client metadata properties were removed. The client's `token_endpoint_auth_method`, and `token_endpoint_auth_signing_alg` properties are now used as the only indication of how a client must authenticate at the introspection endpoint. The accompanying JWA and authentication methods configuration properties were also removed.
* The non-standard `revocation_endpoint_auth_method`, and `revocation_endpoint_auth_signing_alg` client metadata properties were removed. The client's `token_endpoint_auth_method`, and `token_endpoint_auth_signing_alg` properties are now used as the only indication of how a client must authenticate at the revocation endpoint. The accompanying JWA and authentication methods configuration properties were also removed.

### Features

* add UnmetAuthenticationRequirements error ([3f6684a](https://github.com/panva/node-oidc-provider/commit/3f6684a259878eeddc8d5c90fa84635c9e38961b))
* bump DPoP to draft-11 ([917507f](https://github.com/panva/node-oidc-provider/commit/917507fe66e4edf7185886c09e1bac4a714117b6))
* support DPoP nonces ([8d82988](https://github.com/panva/node-oidc-provider/commit/8d82988b0834d631fda17200481883301b993984))


### Performance

* replace native asserts ([1f77781](https://github.com/panva/node-oidc-provider/commit/1f777812584dc9500993a9d100d8aec621f2136e)), closes [#1204](https://github.com/panva/node-oidc-provider/issues/1204) [#1205](https://github.com/panva/node-oidc-provider/issues/1205)


### Refactor

* change default on allowOmittingSingleRegisteredRedirectUri ([d41bb0f](https://github.com/panva/node-oidc-provider/commit/d41bb0ff06b19d81f64682ffedecc87a7c34e3a3))
* check request_uri_not_supported early ([57b39a2](https://github.com/panva/node-oidc-provider/commit/57b39a28dfcea9f362cd64d1c663ed151240e6a1))
* CIBA and PAR do not automatically turn on JAR ([089fa43](https://github.com/panva/node-oidc-provider/commit/089fa43e62ee2c1d3df4a21e16650d2e501fd0d3))
* Completely removed v6.x way of setting access token formats. ([a2cf235](https://github.com/panva/node-oidc-provider/commit/a2cf23527f00858c92a00284cc5ab857b03029cb))
* default code ttl down from 10 minutes down to 1 minute ([f770e2d](https://github.com/panva/node-oidc-provider/commit/f770e2dadb4cdd09261a3953c6f1c15cef4001ac))
* default dPoPSigningAlgValues changed ([9859969](https://github.com/panva/node-oidc-provider/commit/98599690263144ee7f96922b481286e04d30a6be))
* default JAR mode is now strict instead of lax ([cef63b6](https://github.com/panva/node-oidc-provider/commit/cef63b6a75abee6ea934daf62299b5457668b634))
* disable query string bearer by default ([059557b](https://github.com/panva/node-oidc-provider/commit/059557b532de7e8a0734f73c97db2f2eaa56d189))
* disable request_uri support by default ([3575584](https://github.com/panva/node-oidc-provider/commit/3575584ca6a33e97a1288af6fba3669c21ad65ce))
* enable PAR by default ([4272027](https://github.com/panva/node-oidc-provider/commit/42720276fe14c4420ec1ee2f9925d2b6123d936d))
* expiresWithSession on authorization endpoint access tokens ([cb67083](https://github.com/panva/node-oidc-provider/commit/cb670834c8e892e3b25345cc92d207bafc12c8f7))
* oidc-provider is now an ESM-only module ([3c5ebe1](https://github.com/panva/node-oidc-provider/commit/3c5ebe1070d92c40143b7a7874c0d0c454a2231e))
* PBKDF2 JWE encryption algorithms are no longer supported ([868ab2f](https://github.com/panva/node-oidc-provider/commit/868ab2f15f48da9bd104cea5e8e85916d079cf8f))
* redo fapi profile checks, remove x-fapi-headers nonsense ([7cf031a](https://github.com/panva/node-oidc-provider/commit/7cf031a6c1dc554ddff040c3ceaf33d06f61a98b))
* remove default from FAPI profile configuration ([0f93b8c](https://github.com/panva/node-oidc-provider/commit/0f93b8c6c354fbe4271b7d9cba707f4041fd99d7))
* remove introspection and revocation client metadata ([a6433d0](https://github.com/panva/node-oidc-provider/commit/a6433d04c16a22e8d664dada2226d7f5124605e4))
* removed default outgoing cacheable-lookup use ([7c10920](https://github.com/panva/node-oidc-provider/commit/7c109208e7363db195527a26d08e172fcf0d4a04))
* removed optional "none" JWS algorithm support ([e654fe6](https://github.com/panva/node-oidc-provider/commit/e654fe6e1ff1d6c72113a240ab15b77a34058790))
* removed PASETO access token format support ([079e2f2](https://github.com/panva/node-oidc-provider/commit/079e2f27bc66efcf4910672de815dc22abe25ec6))
* removed support for issuing `"cty": "json"` JWEs ([b4b837b](https://github.com/panva/node-oidc-provider/commit/b4b837b4642f3f7bde49e73b43f63ac711935079))
* renamed client auth related configuration ([b8e8ce9](https://github.com/panva/node-oidc-provider/commit/b8e8ce9a8844db732b49a9e1e949045565561087))
* require Node.js LTS 18 ([ff26cf6](https://github.com/panva/node-oidc-provider/commit/ff26cf6890561c1a0fe677c4466f978c506e20de))
* rotated registration management access tokens by default ([2eb5c63](https://github.com/panva/node-oidc-provider/commit/2eb5c633add5c45326b04b846f96e370da9e385c))
* RSA1_5 JWE encryption algorithm is no longer supported ([a967a4e](https://github.com/panva/node-oidc-provider/commit/a967a4eba384ae2f61acd18a959b8e9b31acf32d))
* set default clock skew tolerance to 15 seconds ([42c00da](https://github.com/panva/node-oidc-provider/commit/42c00dabccd950990015ce48ed3f9a7e60594abc))
* update http request options ([2fd5eda](https://github.com/panva/node-oidc-provider/commit/2fd5edafeac7c7b839bcc4c675c062310cc1caf5))

## [7.14.3](https://github.com/panva/node-oidc-provider/compare/v7.14.2...v7.14.3) (2022-12-01)


### Fixes

* memory adapter grant references for intended models ([357ced3](https://github.com/panva/node-oidc-provider/commit/357ced3924b71819be144f184861a8c78c27fde6))

## [7.14.2](https://github.com/panva/node-oidc-provider/compare/v7.14.1...v7.14.2) (2022-11-30)


### Fixes

* build client symmetric keys from all client signing alg properties ([a26f87d](https://github.com/panva/node-oidc-provider/commit/a26f87d74fcc38e48da2814b9e41e84f7e64e784))

## [7.14.1](https://github.com/panva/node-oidc-provider/compare/v7.14.0...v7.14.1) (2022-11-22)


### Fixes

* url encode client_id returned in registration responses ([500dfeb](https://github.com/panva/node-oidc-provider/commit/500dfeb763bd8ea445ad3c79be8e543ba34af275))

## [7.14.0](https://github.com/panva/node-oidc-provider/compare/v7.13.0...v7.14.0) (2022-11-09)


### Features

* graduate jwtResponseModes (JARM) feature as stable ([7b878cd](https://github.com/panva/node-oidc-provider/commit/7b878cd195da05024a45c0e347546f0d4ee862c5))

## [7.13.0](https://github.com/panva/node-oidc-provider/compare/v7.12.0...v7.13.0) (2022-10-26)


### Features

* enable v18 LTS in package.json ([e423b4d](https://github.com/panva/node-oidc-provider/commit/e423b4d87a6caf490d993e8ae4e2b428504f7d8b))

## [7.12.0](https://github.com/panva/node-oidc-provider/compare/v7.11.5...v7.12.0) (2022-09-13)


### Features

* graduate backchannelLogout feature as stable ([617e260](https://github.com/panva/node-oidc-provider/commit/617e2602d0e862fdbdec4d501555097596378d96))


### Fixes

* ignore instead of throw on unverified post_logout_redirect_uri ([04b1096](https://github.com/panva/node-oidc-provider/commit/04b1096ac1507cab15a680ebde91cc33f6d636eb))

## [7.11.5](https://github.com/panva/node-oidc-provider/compare/v7.11.4...v7.11.5) (2022-07-16)


### Fixes

* **PAR:** set additional stored PAR object properties on plain requests ([1be15fa](https://github.com/panva/node-oidc-provider/commit/1be15faed0a704bf5a2c34121d8131e00f23c734))
* **PAR:** skip stored PAR object alg validation when it's being used ([406caa4](https://github.com/panva/node-oidc-provider/commit/406caa48f0c5929666e43a7b76af9a393c4631d2))

## [7.11.4](https://github.com/panva/node-oidc-provider/compare/v7.11.3...v7.11.4) (2022-07-04)


### Fixes

* arrow & static class methods as adapter factories ([#1197](https://github.com/panva/node-oidc-provider/issues/1197)) ([cee552f](https://github.com/panva/node-oidc-provider/commit/cee552f0403863d9a1b8495b93098cc706f7f625))

## [7.11.3](https://github.com/panva/node-oidc-provider/compare/v7.11.2...v7.11.3) (2022-06-13)


### Fixes

* httpOptions helper ([#1194](https://github.com/panva/node-oidc-provider/issues/1194)) ([80fe961](https://github.com/panva/node-oidc-provider/commit/80fe9619cd679b5988820e5389b027a4b0a24ca2))

## [7.11.2](https://github.com/panva/node-oidc-provider/compare/v7.11.1...v7.11.2) (2022-05-16)


### Fixes

* updated `signed` to `trusted` in the Interaction model ([#1192](https://github.com/panva/node-oidc-provider/issues/1192)) ([eb91aea](https://github.com/panva/node-oidc-provider/commit/eb91aea9c3a50284e71f43ce2fe7f31ebdd83bb5))

## [7.11.1](https://github.com/panva/node-oidc-provider/compare/v7.11.0...v7.11.1) (2022-04-25)


### Fixes

* client schema invalidation code not set ([edf22fb](https://github.com/panva/node-oidc-provider/commit/edf22fba1ca8fb21e528c6755f74ae48a9d6704b))

## [7.11.0](https://github.com/panva/node-oidc-provider/compare/v7.10.6...v7.11.0) (2022-04-20)


### Features

* allow native app callbacks in client post_logout_redirect_uris ([3fca22b](https://github.com/panva/node-oidc-provider/commit/3fca22bb5dc8dc529c08c596109988a35e110f74))
* bump backchannelLogout to draft-07 ([95611d9](https://github.com/panva/node-oidc-provider/commit/95611d9978c1f5c10ae9dbe1d49186983a3b01df))
* graduate issAuthResp feature as stable and enable by default ([e774f60](https://github.com/panva/node-oidc-provider/commit/e774f606ea63271c971aad3d7b5730d0f16c0f52))


### Fixes

* ensure jwt replay detection takes clockTolerance into account ([f167233](https://github.com/panva/node-oidc-provider/commit/f1672336750b8a23ad0c0fa9f3bb2f91ad61397d))

## [7.10.6](https://github.com/panva/node-oidc-provider/compare/v7.10.5...v7.10.6) (2022-01-07)


### Fixes

* substr > slice change in mountPath should have been substring ([adc0d63](https://github.com/panva/node-oidc-provider/commit/adc0d63193c131d7a45f83e4195360a62ef2c522))

## [7.10.5](https://github.com/panva/node-oidc-provider/compare/v7.10.4...v7.10.5) (2022-01-04)


### Fixes

* **resourceIndicators:** await the result of useGrantedResource ([#1173](https://github.com/panva/node-oidc-provider/issues/1173)) ([64a8028](https://github.com/panva/node-oidc-provider/commit/64a802884dc4b990847cda4eacb3dba619ae379d))

## [7.10.4](https://github.com/panva/node-oidc-provider/compare/v7.10.3...v7.10.4) (2021-12-05)


### Fixes

* add iss to error responses when issAuthResp is enabled ([05ac3a8](https://github.com/panva/node-oidc-provider/commit/05ac3a8cc51f18d33e17982b81f1996e6a327e8c))

## [7.10.3](https://github.com/panva/node-oidc-provider/compare/v7.10.2...v7.10.3) (2021-12-04)


### Fixes

* expose invalid_dpop_proof error code and set it to 401 on userinfo ([2628d7e](https://github.com/panva/node-oidc-provider/commit/2628d7e4b81d22a3972e8f82c94b9ec4dd9835d4))

## [7.10.2](https://github.com/panva/node-oidc-provider/compare/v7.10.1...v7.10.2) (2021-11-28)


### Fixes

* use paseto configuration from `getResourceServerInfo` ([#1150](https://github.com/panva/node-oidc-provider/issues/1150)) ([02c821d](https://github.com/panva/node-oidc-provider/commit/02c821d7f16c6421d30ffc449366d4d79d951830))

## [7.10.1](https://github.com/panva/node-oidc-provider/compare/v7.10.0...v7.10.1) (2021-11-16)


### Fixes

* clearly mark that multiple pop mechanisms are not allowed ([49eed4c](https://github.com/panva/node-oidc-provider/commit/49eed4c20b28ef95e7a1a6315783dd3956b8c84a))

## [7.10.0](https://github.com/panva/node-oidc-provider/compare/v7.9.0...v7.10.0) (2021-11-04)


### Features

* duplicate iss and aud as JWE Header Parameters ([b26ea44](https://github.com/panva/node-oidc-provider/commit/b26ea4465b3e45b8e63e69bd08c5de525494dea8))

## [7.9.0](https://github.com/panva/node-oidc-provider/compare/v7.8.1...v7.9.0) (2021-10-26)


### Features

* add LTS Gallium as a supported runtime version ([19b4d0d](https://github.com/panva/node-oidc-provider/commit/19b4d0daa4ca1e05acd2b5651545251fe937ff39))

## [7.8.1](https://github.com/panva/node-oidc-provider/compare/v7.8.0...v7.8.1) (2021-10-12)


### Bug Fixes

* use insufficient_scope instead of invalid_scope at userinfo_endpoint ([ba8a8f0](https://github.com/panva/node-oidc-provider/commit/ba8a8f0188c9a73a0ab0f8b974bea49feb2a87a6))

## [7.8.0](https://github.com/panva/node-oidc-provider/compare/v7.7.0...v7.8.0) (2021-09-15)


### Features

* OAuth 2.0 Pushed Authorization Requests (PAR) is now a stable feature ([3c54d8d](https://github.com/panva/node-oidc-provider/commit/3c54d8ddb85d72fc9432c283b3bea417a895afca))

## [7.7.0](https://github.com/panva/node-oidc-provider/compare/v7.6.0...v7.7.0) (2021-09-02)


### Features

* CIBA Core 1.0 is now a stable feature ([cc8bc0d](https://github.com/panva/node-oidc-provider/commit/cc8bc0d651e8111a144cb3eeaf7f61600dd074f2))

## [7.6.0](https://github.com/panva/node-oidc-provider/compare/v7.5.4...v7.6.0) (2021-08-03)


### Features

* support v3.local, v3.public, and v4.public paseto access tokens format ([aca5813](https://github.com/panva/node-oidc-provider/commit/aca5813a5b7e669f30894102ad925b1aec3f3467))

## [7.5.4](https://github.com/panva/node-oidc-provider/compare/v7.5.3...v7.5.4) (2021-07-21)


### Bug Fixes

* add missing x-ua-compatible to form_post and dag input ([f773669](https://github.com/panva/node-oidc-provider/commit/f77366982b33281226f6b88492e844322da69915)), closes [#1052](https://github.com/panva/node-oidc-provider/issues/1052)

## [7.5.3](https://github.com/panva/node-oidc-provider/compare/v7.5.2...v7.5.3) (2021-07-19)


### Bug Fixes

* memory adapter grant references for intended models ([2fe4dc8](https://github.com/panva/node-oidc-provider/commit/2fe4dc83677cdbc8b0f4cc9dc5fa5cdea336162b))

## [7.5.2](https://github.com/panva/node-oidc-provider/compare/v7.5.1...v7.5.2) (2021-07-19)


### Bug Fixes

* use correct keystore select method for paseto access tokens ([ce394bc](https://github.com/panva/node-oidc-provider/commit/ce394bc15874fcea17a61f913248a72a66bf4945))

## [7.5.1](https://github.com/panva/node-oidc-provider/compare/v7.5.0...v7.5.1) (2021-06-24)


### Bug Fixes

* issue id tokens with claims when resource is used ([#1038](https://github.com/panva/node-oidc-provider/issues/1038)) ([4b16c71](https://github.com/panva/node-oidc-provider/commit/4b16c71983dfa9b8f2bf14008e4858478a916e5d))

## [7.5.0](https://github.com/panva/node-oidc-provider/compare/v7.4.1...v7.5.0) (2021-06-23)


### Features

* use 303 See Other HTTP response status code for built in redirects ([c243bf6](https://github.com/panva/node-oidc-provider/commit/c243bf6b6663c41ff3e75c09b95fb978eba87381))

## [7.4.1](https://github.com/panva/node-oidc-provider/compare/v7.4.0...v7.4.1) (2021-05-29)


### Bug Fixes

* handle backchannel requests in grant revocation ([8fe9aec](https://github.com/panva/node-oidc-provider/commit/8fe9aecdf8d93c7c9f2cca5f9e2e6ffaf65714e9))

## [7.4.0](https://github.com/panva/node-oidc-provider/compare/v7.3.2...v7.4.0) (2021-05-28)


### ⚠ BREAKING CHANGES

* **fapi:** Draft feature `fapiRW` was replaced by a stable `fapi`
feature.
* **fapi:** The default profile for the new `fapi` feature is
Financial-grade API Security Profile 1.0 - Part 2: Advanced (Final) rather than
Financial-grade API - Part 2: Read and Write API Security Profile (ID2).
ID2 albeit being an Implementer's Draft remains a possible
`features.fapi.profile` option

### Features

* **fapi:** FAPI (Final and ID2) is now a stable feature ([4f52a4c](https://github.com/panva/node-oidc-provider/commit/4f52a4cf62d0e2282a8f6a1759725b8633135b83))
* **resourceIndicators:** allow omitting resource parameter at the token endpoint ([0309ec0](https://github.com/panva/node-oidc-provider/commit/0309ec068ef7c347fc8f68bf70a5a1fc79f78d57)), closes [/github.com/panva/node-oidc-provider/discussions/989#discussioncomment-676812](https://github.com/panva//github.com/panva/node-oidc-provider/discussions/989/issues/discussioncomment-676812) [#989](https://github.com/panva/node-oidc-provider/issues/989)
* Client Initiated Backchannel Authentication (CIBA) and FAPI-CIBA-ID1 ([a217484](https://github.com/panva/node-oidc-provider/commit/a217484caa3593e556e9c4c18d0766d878d7f813))


### Bug Fixes

* **deviceFlow:** ensure pairwise device flow clients prove ownership of their jwks_uri ([ec99201](https://github.com/panva/node-oidc-provider/commit/ec9920138d3dda17fe107b77a1361be1a4372089))
* remove default got user-agent ([d65187c](https://github.com/panva/node-oidc-provider/commit/d65187c296770c3b903ccdd9f30c323b5ad36a8b))
* skip validating client redirect_uris presence when not required ([90965bb](https://github.com/panva/node-oidc-provider/commit/90965bb61bb87159fee0513a59849bdaa45e4fff))

## [7.3.2](https://github.com/panva/node-oidc-provider/compare/v7.3.1...v7.3.2) (2021-05-13)


### Bug Fixes

* account claims scope argument type during refresh token exchange ([bd1bee1](https://github.com/panva/node-oidc-provider/commit/bd1bee17a77b6b6746cc19be2984db87169ed5b9)), closes [#1000](https://github.com/panva/node-oidc-provider/issues/1000)

## [7.3.1](https://github.com/panva/node-oidc-provider/compare/v7.3.0...v7.3.1) (2021-04-09)


### Bug Fixes

* store original PAR signed request object after decryption ([fa26e55](https://github.com/panva/node-oidc-provider/commit/fa26e55fac320502119f18e7c1fb576cda6ef0d3))

## [7.3.0](https://github.com/panva/node-oidc-provider/compare/v7.2.0...v7.3.0) (2021-04-08)


### ⚠ BREAKING CHANGES

* DPoP implementation updated to [draft-ietf-oauth-dpop-03](https://tools.ietf.org/html/draft-ietf-oauth-dpop-03)

### Features

* update DPoP implementation to ietf draft 03 ([d08126f](https://github.com/panva/node-oidc-provider/commit/d08126f70fc45ef3c3b10ade692406e3793e27dc))

## [7.2.0](https://github.com/panva/node-oidc-provider/compare/v7.1.3...v7.2.0) (2021-04-01)


### Features

* enable customizing client auth jwt assertion expected audience ([e6286a6](https://github.com/panva/node-oidc-provider/commit/e6286a6dd23444930b2e9b033ab9229790b82ea0))

## [7.1.3](https://github.com/panva/node-oidc-provider/compare/v7.1.2...v7.1.3) (2021-03-24)


### Bug Fixes

* interaction uid is now an alias to its jti, it is not stored anymore either ([2d85768](https://github.com/panva/node-oidc-provider/commit/2d857688eb2bfc0fab6b2f02c3ffbf2b953442f7))
* keyselection for ecdh when both OKP and EC are present ([a0f8f7d](https://github.com/panva/node-oidc-provider/commit/a0f8f7d883106c650ef3cb5b380c39f2e29a6b3b))

## [7.1.2](https://github.com/panva/node-oidc-provider/compare/v7.1.1...v7.1.2) (2021-03-15)


### Bug Fixes

* v1.paseto token alg keystore value to be PS384 instead of RS384 ([ae1f879](https://github.com/panva/node-oidc-provider/commit/ae1f879e10a6079c47727830f8e1aa8d6ef95466))

## [7.1.1](https://github.com/panva/node-oidc-provider/compare/v7.1.0...v7.1.1) (2021-03-10)


### Bug Fixes

* save the grantId reference field with an interaction session ([6cab64e](https://github.com/panva/node-oidc-provider/commit/6cab64e1c28422f4ef3ca558bc5f68578cd92a55))
* typo in consent detail missingOIDClaims -> missingOIDCClaims ([1427383](https://github.com/panva/node-oidc-provider/commit/1427383bb67f296063e7952d0dce0201732c29ba))

## [7.1.0](https://github.com/panva/node-oidc-provider/compare/v7.0.0...v7.1.0) (2021-03-05)


### Features

* allow control of which errors flow back to client's redirect_uri ([219cd45](https://github.com/panva/node-oidc-provider/commit/219cd458480e3526380504c879807475e6818830))
* server_error codes no longer redirect back to clients ([b591d7f](https://github.com/panva/node-oidc-provider/commit/b591d7f0dd9e22ed8e47dc9441548c682bb995f1))

## [7.0.0](https://github.com/panva/node-oidc-provider/compare/v6.31.0...v7.0.0) (2021-03-03)


### ⚠ BREAKING CHANGES

* PAR no longer remaps all errors as
invalid_request_object.
* `IdToken.prototype.issue` now requires the `use`
option.
* JWT Header Parameter `client_id` in Request Objects is
now ignored.
* Request Objects now require `iss` and `aud` claims.
* `OIDCContext.prototype.dPoP` getter was removed.
* BaseToken.prototype.setThumbprint `jkt` mode now
expects the string thumbprint value instead of the jose.JWK instance.
* Client JWKS `kid` values are no longer automatically
calculated per RFC7638 when missing. As a result when client's public
keys are used to encrypt assertions the `kid` header will be missing
when such keys are used.
* Provider constructor will now reject JWKS that serve
no purpose (e.g. are only usable for encryption but encryption is
disabled).
* Client and Provider JWKS are validated to be
syntactically correct as before but only resolve to a `crypto.KeyObject`
when they're used.
* `sector_identifier_uri` is now verified regardless of
client's `subject_type` when provided.
* `response_type=token` is no longer supported
* `Session.prototype.accountId` function was removed, it
is just a property access now.
* Session adapter payload property `account` was renamed
to `accountId`.
* Interactions result `login.account` was renamed to
`login.accountId`
* `Session.prototype.loginAccount` option `account` was
renamed to `accountId`
* TypeScript type definitions are no longer bundled with
the package, instead these will be re-published to DefinitelyTyped.
* `configuration.features.resourceIndicators` was
completely re-implemented.
* `configuration.audiences` helper function was removed,
use the `resourceIndicators` feature instead.
* Access Tokens with an audience can no longer be used
to access the userinfo endpoint.
* Only a single audience ("aud") is permitted in
Access Tokens and Client Credential tokens.
* Structured (JWT and PASETO) access tokens Access Tokens
no longer default to using the clientId as audience, if no audience is
specified an Error is throw indicating that issuing a structured token
is probably not needed for a token only usable at the userinfo_endpoint.
* Only opaque access tokens without an audience may be
used to access the userinfo_endpoint.
* Only opaque access tokens may be introspected using
the introspection_endpoint.
* Only opaque access tokens may be revoked using
the revocation_endpoint.
* Only opaque access tokens get stored using the adapter.
* Structured (JWT and PASETO) access tokens do not get
stored by the adapter anymore.
* `access_token.saved` event is only emitted for opaque
access tokens, non-opaque tokens get emitted via `access_token.issued`.
* PASETO tokens were re-implemented from scratch using
the new resourceIndicators implementation.
* `client_credentials.saved` event is only emitted for
opaque access tokens, non-opaque tokens get emitted via
`client_credentials.issued`.
* Structured (JWT and PASETO) access tokens MUST contain
an audience, an error will be thrown if they don't.
* `formats.jwtAccessTokenSigningAlg` configuration was
removed in favour of Resource Server configuration helpers.
* The default consent prompt interaction details have
changed, these now include `missingOIDCScopes`(`string[]`),
`missingOIDClaims`(`string[]`),
`missingResourceScope`(`{ [resourceIndicator]: string[]`).
* The interaction result `consent` structure changed. It
may now only contain a single property, `grantId` (string) which is
the identifier of a Grant (returned by calling Grant.prototype.save()).
* Session-bound artifacts no longer fail to load when
the session's grant has less scopes than the artifact, instead the
action will work with the intersection of currently granted scopes with
the ones on the artifact.
* Sessions no longer hold the "granted" set of
scopes/claims. This is now tracked in the Grant artifact instead. The
following properties are no longer present on the
`session.authorizations[client_id]` object: rejectedScopes,
rejectedClaims, promptedClaims, promptedScopes.
* The following Session prototype methods have been
removed: acceptedClaimsFor, acceptedScopesFor, promptedClaimsFor,
promptedScopesFor, rejectedClaimsFor, rejectedScopesFor.
* OpenID Connect Session Management draft
implementation was removed. This is due to front-channel becoming more
and more unreliable due to browsers blocking third-party cookie access.
* OpenID Connect Front-Channel Logout draft
implementation was removed. This is due to front-channel becoming more
and more unreliable due to browsers blocking third-party cookie access.
* The `jwt-ietf` token format is now just `jwt`. The
`ietfJWTAccessTokenProfile` feature is therefore obsolete and removed.
The prior `jwt` format may be emulated using the
`formats.customizers.jwt` helper function.
* Default PKCE use policy now enforces the use of PKCE
`code_challenge` for all requests where PKCE applies. Use the
`pkce.required` helper to revert to the old policy if you have a reason
to exempt some clients from this policy.
* `ctx.oidc.uid` is now undefined, no random values are
now generated. In places where `ctx.oidc.uid` was used as a source
of a random value, an always fresh random value is now generated
instead.
* Removed every `DEBUG=*` code other than error ones.
Ways to debug the code will surface through logging in the future.
* The Device Flow feature resume path now longer contains
the user code in the URL. Instead, `deviceCode` is now attached to
`Interaction` models when part of a device authorization grant flow.
* The DeviceCode model now gets `grantId` property
assigned only after successful consent interaction.
* Every interaction now gets a totally unique identifier,
"same grant", which never actually was about grants, or consequent
bounces through interaction will now each get a unique identifier.
* The `features.webMessageResponseMode.scriptNonce`
helper was removed, all inline scripts will now have their sha256
automatically added to CSP script-src directives when one is present.
* `client_id` and `client_secret` values are now checked
to conform to their ABNF syntax (%x20-7E).
* Allowing to omit a redirect_uri parameter for
clients with a single one registered is now disabled by default. You can
re-enable this using the `allowOmittingSingleRegisteredRedirectUri`
configuration option.
* Configuration option `cookies.short.maxAge` was removed.
Use `ttl.Interaction` configuration to define the Interaction TTL which
in turn controls the cookie expiration.
* Configuration option `cookies.long.maxAge` was removed.
Use `ttl.Session` configuration to define the Session TTL which
in turn controls the cookie expiration.
* Configuration option `cookies.short.expires` was
removed.
* Configuration option `cookies.long.expires` was
removed.
* Interaction.prototype.save `ttl` argument is now
required.
* Session.prototype.save `ttl` argument is now required.
* Provider.prototype.requestUriCache getter was removed.
* `features.jwtUserinfo` is disabled by default now.
* Removed "whitelist" Request Object merging strategy
* `requestObjects.mergingStrategy` configuration is now a
string valued "strict" or "lax"
* `requestObjects.mergingStrategy` configuration is now
`requestObjects.mode`.
* Configuration option `whitelistedJWA` is now
`enabledJWA`.
* Removed HS256 as a default-enabled algorithm from the
following configuration values so that all AS-issued assertions are
firm to only come from the AS: `whitelistedJWA.idTokenSigningAlgValues`,
`whitelistedJWA.userinfoSigningAlgValues`,
`whitelistedJWA.introspectionSigningAlgValues`,
`whitelistedJWA.authorizationSigningAlgValues`
* Default JWE Algorithms ("alg") now includes "dir".
* ECDH-ES KW variants are not enabled by default anymore.
* The default for JWT Access Tokens' signing algorithm
is no longer the client's `id_token_signed_response_alg` falling back to
RS256 but rather only the provider's default
`id_token_signed_response_alg`.
* Removed built in support for urn: request uris.
* Renamed RequestUriCache.prototype.resolveWebUri to
RequestUriCache.prototype.resolve
* The `claims` configuration property can no longer be
a `Map` instance, only plain objects are allowed.
* `request_object_signing_alg` no longer means a request
object must be provided, `require_signed_request_object` boolean value
serves that purpose now as per the clarifications made in OIDF and IETF
Working Groups.
* The deprecated `postLogoutSuccessSource` configuration
property was removed, use
`features.rpInitiatedLogout.postLogoutSuccessSource` instead.
* The deprecated `logoutSource` configuration
property was removed, use
`features.rpInitiatedLogout.logoutSource` instead.
* RedirectUriMismatch error was removed.
* `redirect_uri_mismatch` error codes are now
`invalid_redirect_uri`.
* Only www-urlencoded bodies recognize RFC6750 payload
bearer token. On the authorization server this only affects the dynamic
registration features and removes an unintended side effect.
* `extraAccessTokenClaims` helper function is renamed to
`extraTokenClaims`.
* The jwks_uri response is now using the proper content
type `application/jwk-set+json`.
* Default Interaction TTL increased from 10 minutes to
1 hour.
* The following Provider instance getters/setters are
removed: subdomainOffset, proxyIpHeader, maxIpsCount, keys. You can
access the underlying Koa app via `provider.app` if you have the need
to use these.
* Default clientBasedCORS helper return value is now
`false`, you must ergo use this helper to open up cors based on your
policy.
* The deprecated `setS256Thumbprint` token instance
method is removed.
* The deprecated `OIDCContext.prototype.bearer` method
is removed.
* removed `dynamicScopes` configuration option, scope
configuration using pre-configured values is gone in favour of
Resource Indicators refactor.
* httpOptions helper function argument is now just
a URL instance. It no longer receives the "to be executed" http request
options.
* httpOptions helper changed. It can now only return
three properties {
  `timeout`: number,
  `agent`: instanceof https.Agent || http.Agent,
  `lookup`: dns.lookup like option
}
* The deprecated `pkceMethods` configuration property was
removed, use `pkce.methods` instead.
* `provider.setInteractionSession` function was removed.
* `meta` interaction result was removed.
* Structured token constructors now require a client
property with a client instance rather than a clientId property.
* `extraClientMetadata.validator` `ctx` argument is now
the first one.
* Single member audience arrays are now transformed to a
single audience string value instead.
* Introspection response `jti` is not returned for
opaque tokens.
* `OIDCContext` and `Interaction` instance property
`signed` renamed to `trusted`.
* `provider.interactionDetails` now only works if both
`req` and `res` are provided.
* `Provider.prototype.callback` is now a function instead
of a getter.
* Node.js runtime version policy changed. Version
12.19.0 is now the minimum required runtime and *ONLY LTS* releases are
supported. This means "Current" Node releases are not officially
supported and you may get mixed results when using them.

### Features

* added configurable policy for issuing registration access tokens ([f18395f](https://github.com/panva/node-oidc-provider/commit/f18395fd0432e6bb7ae8ad60f519ec7a35a31231))
* allow dynamic session and interaction expiration TTL ([afcb375](https://github.com/panva/node-oidc-provider/commit/afcb3750ca0e2a269ad55627d5a9a19e38f90f57))
* allow pre-existing Grants to be loaded during authorization ([9dc7921](https://github.com/panva/node-oidc-provider/commit/9dc792117060a1e682b35a96bcefbba6851a1402))
* apply max expiration on PAR objects created from a JWT ([03f9d8f](https://github.com/panva/node-oidc-provider/commit/03f9d8f1ab95c769e0f029850f40c55a0f673c79))
* automatically add inline scripts to CSP script-src directives ([85c3f4d](https://github.com/panva/node-oidc-provider/commit/85c3f4d0047fd2bd7aab28d2508f87def0766c93)), closes [#850](https://github.com/panva/node-oidc-provider/issues/850) [#584](https://github.com/panva/node-oidc-provider/issues/584)
* check client_id and client_secret ABNF syntax ([3d0d078](https://github.com/panva/node-oidc-provider/commit/3d0d0786cc88c14cfb72ca0e69f219bc69cdd06f))
* control whether underlying Grant gets destroyed during logout and revocation ([ee74dcf](https://github.com/panva/node-oidc-provider/commit/ee74dcf9901433b94f49f304a42b5fba333e9d77))
* features.resourceIndicators (RFC 8707) is now a stable feature ([84c3a5c](https://github.com/panva/node-oidc-provider/commit/84c3a5cdb78b8ffda53e2cbebd135bc262b27d4d))
* helper function to decide whether to validate client.sector_identifier_uri ([72058a5](https://github.com/panva/node-oidc-provider/commit/72058a5fb786288975e13043bcbad003c77aabbf))
* JWT Access Tokens are now just issued and not stored anymore ([d1ee6b7](https://github.com/panva/node-oidc-provider/commit/d1ee6b7c27b24aa6b7a0626d69e2e524975e6021))
* JWT Access Tokens can now be encrypted with a symmetric secret shared with the recipient ([0f76c65](https://github.com/panva/node-oidc-provider/commit/0f76c6576c0a38b3e9550b6017fccaa915fe918e))
* JWT Access Tokens can now be encrypted with an asymmetric public key of the recipient ([d2a63b7](https://github.com/panva/node-oidc-provider/commit/d2a63b7aa172f0a684157b915099ac4bb04e3c37))
* JWT Access Tokens can now be HMAC-signed with a symmetric secret shared with the recipient ([5041158](https://github.com/panva/node-oidc-provider/commit/504115880b4f937cc9a53cecf6447cad4aa4f3a5))
* omitting redirect_uri for clients with a single one is now optional ([329c577](https://github.com/panva/node-oidc-provider/commit/329c5778549b5596c62243e6f745d903b27892ec))
* opaque token length can now be influenced ([f35764f](https://github.com/panva/node-oidc-provider/commit/f35764fce43fe0899fdb682672e79acb93a66986)), closes [#760](https://github.com/panva/node-oidc-provider/issues/760)
* PAR no longer requires otherwise enabled `features.requestObjects` ([33f3a83](https://github.com/panva/node-oidc-provider/commit/33f3a8332b454f3d1fa2b3de0512bf8904a7b695))
* PASETO Access Tokens are now just issued and not stored anymore ([4efe741](https://github.com/panva/node-oidc-provider/commit/4efe74103bbf091ff0060977b1aa0c8b4517347f))
* PASETO Access Tokens can now be encrypted with a symmetric secret shared with the recipient using v1.local ([2e78582](https://github.com/panva/node-oidc-provider/commit/2e785825ec53dc4be5e3394ee076b22eca69999a))
* PASETO Access Tokens now support both v1.public and v2.public ([dff2a72](https://github.com/panva/node-oidc-provider/commit/dff2a72fc25ff1fee8d52b1f66d4c1d1bc4a0c9e))
* require Node.js version ^12.19.0 || ^14.15.0 ([2a54e33](https://github.com/panva/node-oidc-provider/commit/2a54e33c4f2b18367924ab53aa6be383503afc87))
* require use of PKCE ([aa2bd51](https://github.com/panva/node-oidc-provider/commit/aa2bd514d4e829d9d14aa284859d0dc67e5463b1))
* sector_identifier_uri can be used without pairwise subject_type ([202e4c5](https://github.com/panva/node-oidc-provider/commit/202e4c54a4ac5c40c2f0c2d388c6b70228191079))
* The key used to asymmetrically sign JWT Access Tokens can now be chosen based on its Key ID. ([8b32707](https://github.com/panva/node-oidc-provider/commit/8b327072405f40ea141218cf20cddb90285fd70a))
* The key used to asymmetrically sign PASETO Access Tokens can now be chosen based on its Key ID. ([efd3dab](https://github.com/panva/node-oidc-provider/commit/efd3dab876e7b71f95cc98e9cc7eb4a909bd81c2))


### Bug Fixes

* check DPoP htm as case-sensitive ([33223ff](https://github.com/panva/node-oidc-provider/commit/33223fffa6588359b4e85f8f6c8e7c339ca34461))
* delay FAPI response type/mode check when request_uri is present ([78916b7](https://github.com/panva/node-oidc-provider/commit/78916b7a4b53eeaab531e11233364f587f379c09))
* ignore clockTolerance when verifying stored PAR objects ([c3c2276](https://github.com/panva/node-oidc-provider/commit/c3c22766650a4b0a48ccfd20248237f421fbf97a))
* only www-urlencoded bodies recognize RFC6750 payload bearer token ([4553bd5](https://github.com/panva/node-oidc-provider/commit/4553bd548f8eab5f8f545c3cb10a3f92acc65b42))
* remap `invalid_redirect_uri` as `invalid_request` in PAR ([ceb3cd1](https://github.com/panva/node-oidc-provider/commit/ceb3cd15d6051479cc6925771189c27dec559d06))
* remove legacy accept header value from request uri requests ([4cc28ef](https://github.com/panva/node-oidc-provider/commit/4cc28efa6f42b67b6206915b85ae811954fedb93))
* **typescript:** Interaction.prototype.session structure ([#924](https://github.com/panva/node-oidc-provider/issues/924)) ([76c36c7](https://github.com/panva/node-oidc-provider/commit/76c36c7ca955c75d95fdccc7569dbd11ef5ac00d))


### Refactor

* `OIDCContext` and `Interaction` property `signed` renamed ([0ed56bd](https://github.com/panva/node-oidc-provider/commit/0ed56bdbc9d5ee556eefee77b02000e3b699a2e3))
* audience arrays with 1 member are changed to a single value ([d156983](https://github.com/panva/node-oidc-provider/commit/d1569839d34ce46fdd7ddaa0a6093deb66228ec7))
* by default disabled JWT Userinfo Responses ([5931a59](https://github.com/panva/node-oidc-provider/commit/5931a59cf9b6a35dcf7538905257a951a5bd3611))
* changed default signing algorithm selection method ([995d2d4](https://github.com/panva/node-oidc-provider/commit/995d2d49552019fcc8de1d299f340061d8a9f623))
* clean up RequestUriCache ([8c0b9c5](https://github.com/panva/node-oidc-provider/commit/8c0b9c509863b1e2d1882575a8c41b0187e2f269))
* configuration `whitelistedJWA` is now `enabledJWA` ([d77fd4f](https://github.com/panva/node-oidc-provider/commit/d77fd4f3213ef46cf0ec6fc88e2a46fc24f8481d))
* default clientBasedCORS helper is now false ([4cf4cc6](https://github.com/panva/node-oidc-provider/commit/4cf4cc6f0191aa8b320c7760ea41d4ea7d90c8cd))
* default enabled JWAs ([d8ebde0](https://github.com/panva/node-oidc-provider/commit/d8ebde053d7c32874c495f37bb3bd29b44ad3369))
* default Interaction TTL increased from 10 minutes to 1 hour ([f6c7b5e](https://github.com/panva/node-oidc-provider/commit/f6c7b5e4738582bfa592941c73eecf8fb8de09b6))
* extraClientMetadata.validator arguments reordered ([ea6dc73](https://github.com/panva/node-oidc-provider/commit/ea6dc7363ff7e08e0d640bb5932feaf1455960f2))
* idToken.issue() now requires the `use` option ([d1d9421](https://github.com/panva/node-oidc-provider/commit/d1d9421c18398785fefc168bc2e9cac07b12cae4))
* introspection response `jti` not returned for opaque tokens ([a333aaa](https://github.com/panva/node-oidc-provider/commit/a333aaa0bd2020f7da4784debc0d3af97e4c4460))
* only allow objects as `claims` configuration parameter ([2ac59b7](https://github.com/panva/node-oidc-provider/commit/2ac59b772f5417694962e4c1c21e4469c456e4e8))
* provider.callback is now a function instead of a getter ([e78e573](https://github.com/panva/node-oidc-provider/commit/e78e573aca6a9e1a1ae8d0b77d69160cda7838e9))
* provider.interactionDetails(req, res) now requires res ([2c3a667](https://github.com/panva/node-oidc-provider/commit/2c3a667de583846470921883918f4c4145bef6c6))
* provider's jwks_uri is now application/jwk-set+json content ([285eb41](https://github.com/panva/node-oidc-provider/commit/285eb4131f16efcd465e3bc2386347b0808192b5))
* remove bundled TypeScript type defintions ([3a6b671](https://github.com/panva/node-oidc-provider/commit/3a6b671ce10530881f8dd6835371e76d67cb0eb3))
* remove deprecated `pkceMethods` configuration property ([65712d0](https://github.com/panva/node-oidc-provider/commit/65712d0887b23aaa832a843d3485accf4895504d))
* remove deprecated `setS256Thumbprint` token instance method ([6afaf31](https://github.com/panva/node-oidc-provider/commit/6afaf3139c3d4c3c0db097cf44efc9bffd7f3782))
* remove few deprecated configuration properties ([1767c8f](https://github.com/panva/node-oidc-provider/commit/1767c8ffc233d63a5fbc6aebdfc95006fab69775))
* remove Provider.prototype.requestUriCache ([e8b411c](https://github.com/panva/node-oidc-provider/commit/e8b411c4b1615a2fabd2ccec1bf9fd8dd158d30c))
* remove the deprecated `OIDCContext.prototype.bearer` method ([52000d5](https://github.com/panva/node-oidc-provider/commit/52000d55a2452a66917d9a567bf0530ac767bb12))
* removed `dynamicScopes` configuration option ([285fc7a](https://github.com/panva/node-oidc-provider/commit/285fc7ab8b49b8b179232b5fa6c50dd47b0f76f2))
* removed a bunch of proxied methods from provider to app ([3fb32e7](https://github.com/panva/node-oidc-provider/commit/3fb32e7eb5d2ec50902ff913d8dae7398808f15a))
* removed oidc.uid, removed a lot of debug ([801d28f](https://github.com/panva/node-oidc-provider/commit/801d28f01e4f391ffbc2a0d22abf01f415e2cabf))
* Removed OpenID Connect Front-Channel Logout ([feecb5e](https://github.com/panva/node-oidc-provider/commit/feecb5eaa1cea3e0a474ab036c328b1f8e150914))
* Removed OpenID Connect Session Management ([224dd38](https://github.com/panva/node-oidc-provider/commit/224dd38fe1d43bf646c017bdfa7eaac3f3ef1518))
* removed provider.setInteractionSession and result meta object ([ac1b0f6](https://github.com/panva/node-oidc-provider/commit/ac1b0f68472d48c6e42502260cb6206e683a6457))
* rename session.account to session.accountId for consistency ([3e81740](https://github.com/panva/node-oidc-provider/commit/3e817405d44bf25725b763f5cb88a9d8d26195c7))
* renamed `extraAccessTokenClaims` helper function ([ce57d6d](https://github.com/panva/node-oidc-provider/commit/ce57d6d38c2803c4f004cdf0be707c6be92b3d43))
* replaced the `jwt` format with `jwt-ietf` as it is stable now ([d61b515](https://github.com/panva/node-oidc-provider/commit/d61b51596501df8df4f740056aa7fa6e94a13149))
* request_object_signing_alg no longer forces request object use ([e7309af](https://github.com/panva/node-oidc-provider/commit/e7309af980e33f9b54104781ee32c3bb7c539e79))
* requestObjects.mergingStrategy "whitelist" was removed ([7b10e9f](https://github.com/panva/node-oidc-provider/commit/7b10e9f519c470d2c36d64c4831a11d98456b1e9))
* require client in structured tokens constructors ([a4e02bd](https://github.com/panva/node-oidc-provider/commit/a4e02bdb5b1a97474a69e0e3bbf4f46adf2dfb7b))
* response_type value `token` is no longer supported ([0c74a1a](https://github.com/panva/node-oidc-provider/commit/0c74a1a2e3594155613b9471174d32a2279803c3))
* updated `got` http request library ([b395a0d](https://github.com/panva/node-oidc-provider/commit/b395a0dce8ca6eac25d197b77eb225d99bcdc324))
* use invalid_redirect_uri over redirect_uri_mismatch error ([2565cce](https://github.com/panva/node-oidc-provider/commit/2565cce57f94daf5df67569b35eefc3f9f48af14))
* use jose@3 instead of jose@2 ([5572e0e](https://github.com/panva/node-oidc-provider/commit/5572e0e193c92cd59b4ac4ee1addef649eb5a0ae))

## [6.31.0](https://github.com/panva/node-oidc-provider/compare/v6.30.1...v6.31.0) (2021-01-19)


### Features

* end_session_endpoint now recognizes client_id and logout_hint ([9dd2b0e](https://github.com/panva/node-oidc-provider/commit/9dd2b0eaff06959f37e786506d5d2b072e917651))


### Bug Fixes

* keep grants that persist if logged out by that grant's client ([26449f5](https://github.com/panva/node-oidc-provider/commit/26449f5d00625a818674596fa8dd3155c069172b)), closes [#857](https://github.com/panva/node-oidc-provider/issues/857)


### Performance

* use native node's base64url encoding when available ([6149bd3](https://github.com/panva/node-oidc-provider/commit/6149bd37f75a2e49453c1ef25e2ec48fb6ba29f5))

## [6.30.1](https://github.com/panva/node-oidc-provider/compare/v6.30.0...v6.30.1) (2021-01-13)


### Bug Fixes

* botched 6.30.0 release with a syntax error ([cd5f02a](https://github.com/panva/node-oidc-provider/commit/cd5f02a555dcead032178db36a31cce67d808577))

## [6.30.0](https://github.com/panva/node-oidc-provider/compare/v6.29.11...v6.30.0) (2021-01-13)


### Features

* Authorization Server Issuer Identifier in Authorization Response ([3f67ee9](https://github.com/panva/node-oidc-provider/commit/3f67ee90bdebbf62caa8afa84fc4dc0ddaef2dba))
* update JARM feature draft version to Implementer's Draft 01 ([0a021de](https://github.com/panva/node-oidc-provider/commit/0a021de697c67969a2a0ec030500a53ed185d42e))

## [6.29.11](https://github.com/panva/node-oidc-provider/compare/v6.29.10...v6.29.11) (2021-01-12)


### Bug Fixes

* missing login prompt details ([c7b0036](https://github.com/panva/node-oidc-provider/commit/c7b00368d43d4c6c36e32f7e39cbc743e5fae501)), closes [#853](https://github.com/panva/node-oidc-provider/issues/853)

## [6.29.10](https://github.com/panva/node-oidc-provider/compare/v6.29.9...v6.29.10) (2021-01-04)


### Bug Fixes

* html safe guard the action attribute in form post responses ([7cd6025](https://github.com/panva/node-oidc-provider/commit/7cd6025c0e9e66bac2288600ea0870d2e044663d))

## [6.29.9](https://github.com/panva/node-oidc-provider/compare/v6.29.8...v6.29.9) (2020-12-10)


### Bug Fixes

* **typescript:** interaction result may be undefined ([#833](https://github.com/panva/node-oidc-provider/issues/833)) ([44aa53e](https://github.com/panva/node-oidc-provider/commit/44aa53eb0630560eba563d13372b14424daf7f22))
* unrecognized EC curves and OKP subtypes are ignored ([660f46d](https://github.com/panva/node-oidc-provider/commit/660f46d25f5d5fe8e0df0ce0cfdb3a8d8708a3ef))

## [6.29.8](https://github.com/panva/node-oidc-provider/compare/v6.29.7...v6.29.8) (2020-11-30)


### Bug Fixes

* ignore client metadata valued `undefined` when applying defualts ([d0ee50a](https://github.com/panva/node-oidc-provider/commit/d0ee50a23271d1d6655b6552e2fa92e1d049904c)), closes [#824](https://github.com/panva/node-oidc-provider/issues/824)

## [6.29.7](https://github.com/panva/node-oidc-provider/compare/v6.29.6...v6.29.7) (2020-11-10)


### Bug Fixes

* client keystore refresh keeps the derived octet keys in store ([024841e](https://github.com/panva/node-oidc-provider/commit/024841e82ddb5b4ffdd2c66504381f02c6219de8)), closes [#816](https://github.com/panva/node-oidc-provider/issues/816)

## [6.29.6](https://github.com/panva/node-oidc-provider/compare/v6.29.5...v6.29.6) (2020-11-08)


### Bug Fixes

* ensure decrypted request object is accessed in PAR responses ([09751d7](https://github.com/panva/node-oidc-provider/commit/09751d75c770ab0b3a9032239abd4ca7b7cba7cf)), closes [#813](https://github.com/panva/node-oidc-provider/issues/813)

## [6.29.5](https://github.com/panva/node-oidc-provider/compare/v6.29.4...v6.29.5) (2020-10-03)


### Bug Fixes

* loopback redirectUriAllowed protocol check ([#794](https://github.com/panva/node-oidc-provider/issues/794)) ([da99330](https://github.com/panva/node-oidc-provider/commit/da993300c2237e794f012b679c483d42c1d9e423))

## [6.29.4](https://github.com/panva/node-oidc-provider/compare/v6.29.3...v6.29.4) (2020-09-19)


### Bug Fixes

* **typescript:** findAccount may return undefined ([#786](https://github.com/panva/node-oidc-provider/issues/786)) ([6689cdb](https://github.com/panva/node-oidc-provider/commit/6689cdb7edeb6e66f70446fb3e7c1266debc631e))
* updated request object mime-type as per draft-ietf-oauth-jwsreq-30 ([f15524a](https://github.com/panva/node-oidc-provider/commit/f15524a049722d2b3c5eb95c31ff0950e930bf29))

## [6.29.3](https://github.com/panva/node-oidc-provider/compare/v6.29.2...v6.29.3) (2020-08-25)


### Bug Fixes

* **typescript:** allows adapter factory in typings ([#776](https://github.com/panva/node-oidc-provider/issues/776)) ([3cfcd77](https://github.com/panva/node-oidc-provider/commit/3cfcd778cb3a9bdecac0ad51dec062daa187e6b0))

## [6.29.2](https://github.com/panva/node-oidc-provider/compare/v6.29.1...v6.29.2) (2020-08-20)


### Bug Fixes

* **typescript:** extend AdapterPayload from AnyClientMetadata ([6631a2d](https://github.com/panva/node-oidc-provider/commit/6631a2d6e43b30ad90a1f2c1e4bdff1fe3686715)), closes [#774](https://github.com/panva/node-oidc-provider/issues/774)

## [6.29.1](https://github.com/panva/node-oidc-provider/compare/v6.29.0...v6.29.1) (2020-08-13)


### Bug Fixes

* **typescript:** add missing rpInitiatedLogout types ([59c389b](https://github.com/panva/node-oidc-provider/commit/59c389b6e78cd4e9968d575dbaf5824edc8a1464))

## [6.29.0](https://github.com/panva/node-oidc-provider/compare/v6.28.0...v6.29.0) (2020-08-12)


### Features

* allow RP-Initiated Logout 1.0 feature to be disabled ([a2ef044](https://github.com/panva/node-oidc-provider/commit/a2ef0449fd5102f3b09218189744be592818859b))
* update backchannelLogout feature draft version ([9a9dd7e](https://github.com/panva/node-oidc-provider/commit/9a9dd7e754cf509f2ae8cb82193ce79627e5ec4a))
* update frontchannelLogout feature draft version ([d54cc8f](https://github.com/panva/node-oidc-provider/commit/d54cc8f8caf145aaa3959f1b3b7eb202e4072976))
* update sessionManagement feature draft version ([aa62927](https://github.com/panva/node-oidc-provider/commit/aa62927ebe8d3832d3dd63de95bddd2590ea6d6f))

## [6.28.0](https://github.com/panva/node-oidc-provider/compare/v6.27.5...v6.28.0) (2020-07-14)


### Bug Fixes

* ensure client is still valid after custom metadata processing ([fded7c6](https://github.com/panva/node-oidc-provider/commit/fded7c674199668321f08af15be4f0a01092d4c1))


### Features

* incorporate behaviours and metadata from jwsreq-25 ([cb12761](https://github.com/panva/node-oidc-provider/commit/cb12761bf15b877d3bf878eea7f1fbd267a020ea))
* update PAR implementation to ietf draft 02 ([fd2ccee](https://github.com/panva/node-oidc-provider/commit/fd2ccee437572e01c1afb60b58d5386b93d5e992))



## [6.27.5](https://github.com/panva/node-oidc-provider/compare/v6.27.4...v6.27.5) (2020-07-06)



## [6.27.4](https://github.com/panva/node-oidc-provider/compare/v6.27.3...v6.27.4) (2020-06-30)



## [6.27.3](https://github.com/panva/node-oidc-provider/compare/v6.27.2...v6.27.3) (2020-06-19)


### Bug Fixes

* re-allow transfer-encoding chunked ([f88447b](https://github.com/panva/node-oidc-provider/commit/f88447bf989a208d7e0490dbe3226c534259c442)), closes [#739](https://github.com/panva/node-oidc-provider/issues/739)



## [6.27.2](https://github.com/panva/node-oidc-provider/compare/v6.27.1...v6.27.2) (2020-06-16)


### Bug Fixes

* remove unintended client_id from post_logout_redirect_uri callbacks ([57d07cd](https://github.com/panva/node-oidc-provider/commit/57d07cd14a6d18681ee0953c28f4ebe7fda3681c))



## [6.27.1](https://github.com/panva/node-oidc-provider/compare/v6.27.0...v6.27.1) (2020-06-15)


### Bug Fixes

* correct jwtIntrospection draft ack version ([#735](https://github.com/panva/node-oidc-provider/issues/735)) ([62b97d4](https://github.com/panva/node-oidc-provider/commit/62b97d4e6a47cbbbe2d9216a31988a6d442689bf))
* **typescript:** static IdToken.validate ([#733](https://github.com/panva/node-oidc-provider/issues/733)) ([a0d997e](https://github.com/panva/node-oidc-provider/commit/a0d997e9a8653cddaa95ae31b0bea6bdaa1e0267))



## [6.27.0](https://github.com/panva/node-oidc-provider/compare/v6.26.1...v6.27.0) (2020-06-01)


### Bug Fixes

* allow any JSON numeric value for timestamp values for DPoP JWTs ([0700fde](https://github.com/panva/node-oidc-provider/commit/0700fde4e9fb6b4b0a718fb323d1e3d955a1be43))


### Features

* secp256k1 EC curve and ES256K JWS alg feature flag removed ([f74f6bd](https://github.com/panva/node-oidc-provider/commit/f74f6bdf3eea8b6e97c735b697e49779a70b4d1c))


### BREAKING CHANGES

* secp256k1 and ES256K have been registered in IANA a few
days ago so the flag is not needed anymore.

Note: Updates to draft specification versions are released as MINOR
library versions, if you utilize these specification implementations
consider using the tilde `~` operator in your package.json since
breaking changes may be introduced as part of these version updates.
Alternatively, [acknowledge](/docs/README.md#features) the version and
be notified of breaking changes as part of your CI.



## [6.26.1](https://github.com/panva/node-oidc-provider/compare/v6.26.0...v6.26.1) (2020-05-18)


### Bug Fixes

* **typescript:** claims/scopes as Set in rejected/prompted functions ([#719](https://github.com/panva/node-oidc-provider/issues/719)) ([950c21d](https://github.com/panva/node-oidc-provider/commit/950c21d909b84c9de915ed30cff4d6f1f7cc95f7))
* **typescript:** undefined return for DefaultPolicy.get and Checks.get ([b61e9d8](https://github.com/panva/node-oidc-provider/commit/b61e9d886c3f5655374f2e70323fa272b5242adb))



## [6.26.0](https://github.com/panva/node-oidc-provider/compare/v6.25.0...v6.26.0) (2020-05-12)


### Bug Fixes

* A192CBC-HS384 and A256CBC-HS512 direct encryption key derivation ([ead23a7](https://github.com/panva/node-oidc-provider/commit/ead23a76ea3539618c62ecd8974d55e5c76ebcda))


### Features

* helper to define PKCE use requirement ([0c2e208](https://github.com/panva/node-oidc-provider/commit/0c2e208f928dbe7960ccfcc6516b1730a2ff83c0))



## [6.25.0](https://github.com/panva/node-oidc-provider/compare/v6.24.0...v6.25.0) (2020-05-05)


### Bug Fixes

* **typescript:** fix metaFor "value" argument type ([0b31b69](https://github.com/panva/node-oidc-provider/commit/0b31b690baa6a93e2c308990d5a11edcca4e2cd3)), closes [#711](https://github.com/panva/node-oidc-provider/issues/711)


### Features

* update DPoP implementation to ietf draft 01 ([330d13c](https://github.com/panva/node-oidc-provider/commit/330d13cfe2eee22d1745909e90cab738e71e8f5d))


### BREAKING CHANGES

* DPoP implementation updated to
[draft-ietf-oauth-dpop-01](https://tools.ietf.org/html/draft-ietf-oauth-dpop-01)

Note: Updates to draft specification versions are released as MINOR
library versions, if you utilize these specification implementations
consider using the tilde `~` operator in your package.json since
breaking changes may be introduced as part of these version updates.
Alternatively, [acknowledge](/docs/README.md#features) the version and
be notified of breaking changes as part of your CI.



## [6.24.0](https://github.com/panva/node-oidc-provider/compare/v6.23.5...v6.24.0) (2020-04-27)


### Bug Fixes

* **typescript:** added types of prompt.checks in interaction policy ([3b97bde](https://github.com/panva/node-oidc-provider/commit/3b97bdef30e287893ba28c9893b9638efde9eb59))


### Features

* **typescript:** export the DefaultPolicy interface ([b36190b](https://github.com/panva/node-oidc-provider/commit/b36190b9f3e93634d42dfd7fd7ab6ba212465231)), closes [#707](https://github.com/panva/node-oidc-provider/issues/707)
* add server-wide policy configuration on accepting tokens in query ([90b400a](https://github.com/panva/node-oidc-provider/commit/90b400a2ee8954b8e965752df97b19ddeb60dcea))
* introspection response allowedPolicy helper function added ([e59cc66](https://github.com/panva/node-oidc-provider/commit/e59cc6600bfa9acf96f491f9e2ea9345c7c664a2)), closes [#642](https://github.com/panva/node-oidc-provider/issues/642)
* update features.jwtIntrospection to draft 09 ([219e8c3](https://github.com/panva/node-oidc-provider/commit/219e8c3df230737c175e9fb9b318c4bd1c0ef011))



## [6.23.5](https://github.com/panva/node-oidc-provider/compare/v6.23.4...v6.23.5) (2020-04-09)


### Bug Fixes

* revert "chore: update tree router" ([13e4142](https://github.com/panva/node-oidc-provider/commit/13e4142b57bc6c9961479d1af15a6612cba7a760)), closes [#696](https://github.com/panva/node-oidc-provider/issues/696)



## [6.23.4](https://github.com/panva/node-oidc-provider/compare/v6.23.3...v6.23.4) (2020-04-03)


### Bug Fixes

* **typescript:** added revokeByGrantId types to appropriate models ([883b038](https://github.com/panva/node-oidc-provider/commit/883b0389470f5658aea4da313dac17c487e485c7))



## [6.23.3](https://github.com/panva/node-oidc-provider/compare/v6.23.2...v6.23.3) (2020-03-22)


### Bug Fixes

* client jwks_uri are now fetched with a lock, cooldown improvements ([b193010](https://github.com/panva/node-oidc-provider/commit/b193010c4a110335e09be2524eef4b27701e2f8f))



## [6.23.2](https://github.com/panva/node-oidc-provider/compare/v6.23.1...v6.23.2) (2020-03-16)


### Bug Fixes

* return `iss` to introspection responses ([f1b6fb4](https://github.com/panva/node-oidc-provider/commit/f1b6fb40aa06c8d95cb5e2f833cd55fb6b132725)), closes [#676](https://github.com/panva/node-oidc-provider/issues/676)



## [6.23.1](https://github.com/panva/node-oidc-provider/compare/v6.23.0...v6.23.1) (2020-03-04)


### Bug Fixes

* allow client registration update fields to be omitted by the client ([9df9bd7](https://github.com/panva/node-oidc-provider/commit/9df9bd74bccb44f88a9008483afb13f43cf610e6)), closes [#664](https://github.com/panva/node-oidc-provider/issues/664)



## [6.23.0](https://github.com/panva/node-oidc-provider/compare/v6.22.1...v6.23.0) (2020-03-03)


### Bug Fixes

* client credentials exchange checks the client's scope whitelist ([5e4defc](https://github.com/panva/node-oidc-provider/commit/5e4defcc8a9fa174c2ce4826078ac818be21eab8))
* stable features with ack now throw to indicate a possible breaking change ([cf58d35](https://github.com/panva/node-oidc-provider/commit/cf58d357717fe70ca363a1d41bf26d7c7544786c))
* **typescript:** adapter methods typings and interface name typo ([e086fc6](https://github.com/panva/node-oidc-provider/commit/e086fc66464b71e9f95df74fecefc16d41b7b96a))


### Features

* features.mTLS (RFC 8705) is now a stable feature ([cfeaca8](https://github.com/panva/node-oidc-provider/commit/cfeaca810cf62eee3e1b798954389264be9fea03))



## [6.22.1](https://github.com/panva/node-oidc-provider/compare/v6.22.0...v6.22.1) (2020-02-28)


### Bug Fixes

* **typescript:** correct KoaContextWithOIDC definition, take 2 ([84d32fc](https://github.com/panva/node-oidc-provider/commit/84d32fc1addd88c0198c66dba4d720bc1b8c1c71)), closes [#659](https://github.com/panva/node-oidc-provider/issues/659)



## [6.22.0](https://github.com/panva/node-oidc-provider/compare/v6.21.1...v6.22.0) (2020-02-28)


### Bug Fixes

* **typescript:** correct KoaContextWithOIDC definition ([655ea29](https://github.com/panva/node-oidc-provider/commit/655ea2954f30093e9d19fadb98c453b17d8ce192)), closes [#659](https://github.com/panva/node-oidc-provider/issues/659)


### Features

* more ctx entities to accomodate [#658](https://github.com/panva/node-oidc-provider/issues/658) ([51b128d](https://github.com/panva/node-oidc-provider/commit/51b128d8f9ece755ea4109752aca5287792b63d8))



## [6.21.1](https://github.com/panva/node-oidc-provider/compare/v6.21.0...v6.21.1) (2020-02-27)


### Bug Fixes

* check that session account is a string ([e1eb211](https://github.com/panva/node-oidc-provider/commit/e1eb211618a2f9f2470d8cad00660805c7dc88a2)), closes [#650](https://github.com/panva/node-oidc-provider/issues/650) [#655](https://github.com/panva/node-oidc-provider/issues/655)



## [6.21.0](https://github.com/panva/node-oidc-provider/compare/v6.20.3...v6.21.0) (2020-02-18)


### Features

* add support for RSA-OAEP-384 and RSA-OAEP-512 JWE algorithms ([c669bd1](https://github.com/panva/node-oidc-provider/commit/c669bd1d71a1c2b25e9f04876d8af980730f128e))



## [6.20.3](https://github.com/panva/node-oidc-provider/compare/v6.20.2...v6.20.3) (2020-02-14)


### Bug Fixes

* allow opt-in refresh_token grant without offline_access as in 5.x ([b67a3a6](https://github.com/panva/node-oidc-provider/commit/b67a3a686efa6847d47a6ed18009958ab3b7bc3b)), closes [#647](https://github.com/panva/node-oidc-provider/issues/647)



## [6.20.2](https://github.com/panva/node-oidc-provider/compare/v6.20.1...v6.20.2) (2020-02-11)


### Bug Fixes

* **typescript:** remove @types/node from runtime dependencies ([55a5074](https://github.com/panva/node-oidc-provider/commit/55a50740db9c07104d71cae62afd2831ff02b6b1)), closes [#646](https://github.com/panva/node-oidc-provider/issues/646)



## [6.20.1](https://github.com/panva/node-oidc-provider/compare/v6.20.0...v6.20.1) (2020-02-04)


### Bug Fixes

* `interaction.started` listener second argument type fixed ([2fe67a9](https://github.com/panva/node-oidc-provider/commit/2fe67a96a77220cb70c4b38dd6a8d5ee894e13aa)), closes [#643](https://github.com/panva/node-oidc-provider/issues/643)



## [6.20.0](https://github.com/panva/node-oidc-provider/compare/v6.19.2...v6.20.0) (2020-01-31)


### Features

* allow koa context argument in idFactory and secretFactory ([76aa942](https://github.com/panva/node-oidc-provider/commit/76aa94277653cc62933726680deb28261377d9bd)), closes [#455](https://github.com/panva/node-oidc-provider/issues/455)



## [6.19.2](https://github.com/panva/node-oidc-provider/compare/v6.19.1...v6.19.2) (2020-01-25)


### Bug Fixes

* set samesite compatibility cookie as transient when the session is ([1257164](https://github.com/panva/node-oidc-provider/commit/1257164acdd5d2a4ddaf38f4ec5ef06a969fe0ed)), closes [#636](https://github.com/panva/node-oidc-provider/issues/636)



## [6.19.1](https://github.com/panva/node-oidc-provider/compare/v6.19.0...v6.19.1) (2020-01-25)


### Bug Fixes

* allow ECDH-ES with AES_CBC_HMAC_SHA2 key sizes larger than 256 bits ([a65e9c4](https://github.com/panva/node-oidc-provider/commit/a65e9c4b11a8577761b9fdabe58a5119f04ef3eb))



## [6.19.0](https://github.com/panva/node-oidc-provider/compare/v6.18.2...v6.19.0) (2020-01-23)


### Features

* allow overloading prototype for comparing client secrets ([eec36eb](https://github.com/panva/node-oidc-provider/commit/eec36eb7b160593ac2cf7a5d2b69a00e45542e50)), closes [#631](https://github.com/panva/node-oidc-provider/issues/631)



## [6.18.2](https://github.com/panva/node-oidc-provider/compare/v6.18.1...v6.18.2) (2020-01-16)


### Bug Fixes

* number of default should-change notices using a wrong property ([8e51724](https://github.com/panva/node-oidc-provider/commit/8e5172481181e9b113d7bca20654b9dc230b6d1b))
* principal-change triggered logout fixes ([fa860cf](https://github.com/panva/node-oidc-provider/commit/fa860cfbdaaf3ca9ab46117d1d2673593724f3f3)), closes [#628](https://github.com/panva/node-oidc-provider/issues/628) [#600](https://github.com/panva/node-oidc-provider/issues/600)



## [6.18.1](https://github.com/panva/node-oidc-provider/compare/v6.18.0...v6.18.1) (2020-01-07)


### Bug Fixes

* fix client secret based algorithm keys for clients with jwks ([75d82a0](https://github.com/panva/node-oidc-provider/commit/75d82a0402194393058a2973bce286f1571323d7))



## [6.18.0](https://github.com/panva/node-oidc-provider/compare/v6.17.7...v6.18.0) (2019-12-31)


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



## [6.17.0](https://github.com/panva/node-oidc-provider/compare/v6.16.1...v6.17.0) (2019-12-02)


### Features

* add support for secp256k1 elliptic curve use ([30aa706](https://github.com/panva/node-oidc-provider/commit/30aa70621edb158d5cbea67b47c43db81ecf3f90))



## [6.16.1](https://github.com/panva/node-oidc-provider/compare/v6.16.0...v6.16.1) (2019-11-26)


### Bug Fixes

* use shake256(m, 114) for Ed448 ID Token `*_hash` claims ([7e6ba6f](https://github.com/panva/node-oidc-provider/commit/7e6ba6f42d1e25dde9c112e8098dbdafecc7f9c3))



## [6.16.0](https://github.com/panva/node-oidc-provider/compare/v6.15.2...v6.16.0) (2019-11-16)


### Features

* add script tag nonce resolution helper for session management and wmrm ([#584](https://github.com/panva/node-oidc-provider/issues/584)) ([b32b8e6](https://github.com/panva/node-oidc-provider/commit/b32b8e63595d30771520473f7c1a821fb40337af)), closes [#583](https://github.com/panva/node-oidc-provider/issues/583)



## [6.15.2](https://github.com/panva/node-oidc-provider/compare/v6.15.1...v6.15.2) (2019-11-15)


### Bug Fixes

* ensure BaseModel descendants have an exp property ([22cc547](https://github.com/panva/node-oidc-provider/commit/22cc547ffb45503cf2fc4357958325e0f5ed4b2f)), closes [#580](https://github.com/panva/node-oidc-provider/issues/580)



## [6.15.1](https://github.com/panva/node-oidc-provider/compare/v6.15.0...v6.15.1) (2019-11-14)



## [6.15.0](https://github.com/panva/node-oidc-provider/compare/v6.14.2...v6.15.0) (2019-11-14)


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



## [6.14.0](https://github.com/panva/node-oidc-provider/compare/v6.13.0...v6.14.0) (2019-11-07)


### Bug Fixes

* autosubmit logout when there's no accountId in the session ([c6b1770](https://github.com/panva/node-oidc-provider/commit/c6b1770e68224b7463c1fa5c64199f0cd38131af)), closes [#566](https://github.com/panva/node-oidc-provider/issues/566)
* omit `*_hash` ID Token claims if signed with "none" (code flow only) ([5c540c0](https://github.com/panva/node-oidc-provider/commit/5c540c06ae11bb5ae62eb6f14b7cac66d09f2fa5))


### Features

* add interaction<>session consistency checks ([018255e](https://github.com/panva/node-oidc-provider/commit/018255ed3547667464f1f2837561db593c33bfe8))



## [6.13.0](https://github.com/panva/node-oidc-provider/compare/v6.12.13...v6.13.0) (2019-10-31)


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



## [6.12.0](https://github.com/panva/node-oidc-provider/compare/v6.11.1...v6.12.0) (2019-09-27)


### Features

* handle sameSite=none incompatible user-agents ([4e68415](https://github.com/panva/node-oidc-provider/commit/4e68415))



## [6.11.1](https://github.com/panva/node-oidc-provider/compare/v6.11.0...v6.11.1) (2019-09-24)


### Bug Fixes

* **typescript:** provider.callback getter type regression fixed ([5cea116](https://github.com/panva/node-oidc-provider/commit/5cea116)), closes [#534](https://github.com/panva/node-oidc-provider/issues/534)



## [6.11.0](https://github.com/panva/node-oidc-provider/compare/v6.10.0...v6.11.0) (2019-09-24)


### Bug Fixes

* token TTL being a helper function is now accepted ([a930355](https://github.com/panva/node-oidc-provider/commit/a930355))


### Features

* default refresh token TTL policy for SPAs follows the updated BCP ([d6a2a34](https://github.com/panva/node-oidc-provider/commit/d6a2a34))
* update JWT Response for OAuth Token Introspection to draft 08 ([5f917e2](https://github.com/panva/node-oidc-provider/commit/5f917e2))



## [6.10.0](https://github.com/panva/node-oidc-provider/compare/v6.9.0...v6.10.0) (2019-09-21)


### Bug Fixes

* **typescript:** add missing definitions ([#533](https://github.com/panva/node-oidc-provider/issues/533)) ([c663417](https://github.com/panva/node-oidc-provider/commit/c663417))


### Features

* update FAPI RW behaviours ([a7ed27a](https://github.com/panva/node-oidc-provider/commit/a7ed27a))
* update pushed authorization requests draft ([aaf5740](https://github.com/panva/node-oidc-provider/commit/aaf5740))



## [6.9.0](https://github.com/panva/node-oidc-provider/compare/v6.8.0...v6.9.0) (2019-09-17)


### Features

* added TypeScript definitions ([#530](https://github.com/panva/node-oidc-provider/issues/530)) ([5adf5a8](https://github.com/panva/node-oidc-provider/commit/5adf5a8))



## [6.8.0](https://github.com/panva/node-oidc-provider/compare/v6.7.0...v6.8.0) (2019-09-06)


### Features

* update fapiRW draft feature ([8b927fc](https://github.com/panva/node-oidc-provider/commit/8b927fc))
* update pushed request objects to b6cd952 ([43fa8aa](https://github.com/panva/node-oidc-provider/commit/43fa8aa))



## [6.7.0](https://github.com/panva/node-oidc-provider/compare/v6.6.2...v6.7.0) (2019-08-30)


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



## [6.6.0](https://github.com/panva/node-oidc-provider/compare/v6.5.0...v6.6.0) (2019-08-23)


### Bug Fixes

* properly apply samesite=none for non-webkit browsers ([ec2ffc6](https://github.com/panva/node-oidc-provider/commit/ec2ffc6))


### Features

* added Node.js lts/dubnium support ([52e914c](https://github.com/panva/node-oidc-provider/commit/52e914c))



## [6.5.0](https://github.com/panva/node-oidc-provider/compare/v6.4.2...v6.5.0) (2019-08-20)


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



## [6.4.0](https://github.com/panva/node-oidc-provider/compare/v6.3.0...v6.4.0) (2019-08-07)


### Bug Fixes

* paseto formatted access token audience is a single string ([1fd45f5](https://github.com/panva/node-oidc-provider/commit/1fd45f5))
* properly check if resourceIndicators is enabled ([bbcdca2](https://github.com/panva/node-oidc-provider/commit/bbcdca2))


### Features

* added a helper for validating provided resource indicator values ([a97ffdc](https://github.com/panva/node-oidc-provider/commit/a97ffdc)), closes [#487](https://github.com/panva/node-oidc-provider/issues/487)
* allow audiences helper to return a single string audience ([4c7a3a8](https://github.com/panva/node-oidc-provider/commit/4c7a3a8))
* draft implementation of IETF JWT Access Token profile ([e690462](https://github.com/panva/node-oidc-provider/commit/e690462))



## [6.3.0](https://github.com/panva/node-oidc-provider/compare/v6.2.2...v6.3.0) (2019-08-04)


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



## [6.2.0](https://github.com/panva/node-oidc-provider/compare/v6.1.2...v6.2.0) (2019-07-21)


### Features

* mTLS stable release candidate ([a999452](https://github.com/panva/node-oidc-provider/commit/a999452))



## [6.1.2](https://github.com/panva/node-oidc-provider/compare/v6.1.1...v6.1.2) (2019-07-12)


### Bug Fixes

* acknowledging tls client auth draft fixed ([02df82a](https://github.com/panva/node-oidc-provider/commit/02df82a))



## [6.1.1](https://github.com/panva/node-oidc-provider/compare/v6.1.0...v6.1.1) (2019-07-12)


### Bug Fixes

* bump acknowledgable draft versions that don't need code changes ([55b4770](https://github.com/panva/node-oidc-provider/commit/55b4770))



## [6.1.0](https://github.com/panva/node-oidc-provider/compare/v6.0.3...v6.1.0) (2019-07-10)


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



## [6.0.0](https://github.com/panva/node-oidc-provider/compare/v5.5.5...v6.0.0) (2019-06-28)

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



## [5.5.5](https://github.com/panva/node-oidc-provider/compare/v5.5.4...v5.5.5) (2019-02-20)


### Bug Fixes

* expose only supported cors methods ([4a81104](https://github.com/panva/node-oidc-provider/commit/4a81104))
* replace router again to fix CORS preflights ([d642f8b](https://github.com/panva/node-oidc-provider/commit/d642f8b))



## [5.5.4](https://github.com/panva/node-oidc-provider/compare/v5.5.3...v5.5.4) (2019-02-15)


### Refactored

* removed koa-router in favor of koa-trie-router ([fe812e0](https://github.com/panva/node-oidc-provider/commit/fe812e0)), closes [#436](https://github.com/panva/node-oidc-provider/issues/436)


## [5.5.3](https://github.com/panva/node-oidc-provider/compare/v5.5.2...v5.5.3) (2019-01-22)


### Bug Fixes

* handle server_error when refresh tokens are missing `gty` ([75046ca](https://github.com/panva/node-oidc-provider/commit/75046ca))



## [5.5.2](https://github.com/panva/node-oidc-provider/compare/v5.5.1...v5.5.2) (2018-12-20)


### Bug Fixes

* JWKStore prototype jwksUri undefined client ([#413](https://github.com/panva/node-oidc-provider/issues/413)) ([ba69fb6](https://github.com/panva/node-oidc-provider/commit/ba69fb6))



## [5.5.1](https://github.com/panva/node-oidc-provider/compare/v5.5.0...v5.5.1) (2018-11-26)


### Bug Fixes

* added aud and azp validations for ID Tokens passed by clients ([4df8160](https://github.com/panva/node-oidc-provider/commit/4df8160))
* aud for jwt oauth tokens no longer gets the client id pushed in ([14c556e](https://github.com/panva/node-oidc-provider/commit/14c556e))



## [5.5.0](https://github.com/panva/node-oidc-provider/compare/v5.4.2...v5.5.0) (2018-11-22)


### Bug Fixes

* gracefully handle mixed up response_type(s) order ([b775591](https://github.com/panva/node-oidc-provider/commit/b775591))
* http2 is also stable in ^8.13.0 ([3d240d9](https://github.com/panva/node-oidc-provider/commit/3d240d9))


### Features

* initial and registration access token policies ([452000c](https://github.com/panva/node-oidc-provider/commit/452000c)), closes [#394](https://github.com/panva/node-oidc-provider/issues/394)



## [5.4.2](https://github.com/panva/node-oidc-provider/compare/v5.4.1...v5.4.2) (2018-11-19)


### Bug Fixes

* ignore `*_endpoint_auth_signing_alg` client metadata when `_jwt` auth is not allowed ([d0346a8](https://github.com/panva/node-oidc-provider/commit/d0346a8))



## [5.4.1](https://github.com/panva/node-oidc-provider/compare/v5.4.0...v5.4.1) (2018-11-19)


### Bug Fixes

* require consent result to save accepted scopes and claims ([7720367](https://github.com/panva/node-oidc-provider/commit/7720367))



## [5.4.0](https://github.com/panva/node-oidc-provider/compare/v5.3.0...v5.4.0) (2018-11-18)


### Bug Fixes

* handle potentially unvalidated response mode in authz error handler ([ee501d1](https://github.com/panva/node-oidc-provider/commit/ee501d1))
* issue new session identifiers when session changes ([56d04e6](https://github.com/panva/node-oidc-provider/commit/56d04e6))
* omit saving an empty session on initial authorize request ([d0b7069](https://github.com/panva/node-oidc-provider/commit/d0b7069))


### Features

* allow omitting redirect_uri in code exchange at the token endpoint when there is just one registered ([8cdd407](https://github.com/panva/node-oidc-provider/commit/8cdd407))
* update of draft-ietf-oauth-resource-indicators from 00 to 01 ([1302a54](https://github.com/panva/node-oidc-provider/commit/1302a54)), closes [#385](https://github.com/panva/node-oidc-provider/issues/385)



## [5.3.0](https://github.com/panva/node-oidc-provider/compare/v5.2.0...v5.3.0) (2018-11-05)


### Bug Fixes

* upgrade min node-jose version to fix its performance in node ([f1cb4c6](https://github.com/panva/node-oidc-provider/commit/f1cb4c6))


### Features

* sessionManagement frame uses Storage Access API to detect errors ([156e12d](https://github.com/panva/node-oidc-provider/commit/156e12d))



## [5.2.0](https://github.com/panva/node-oidc-provider/compare/v5.1.2...v5.2.0) (2018-11-01)


### Draft Features

* sessionManagement feature doesn't set a default thirdPartyCheckUrl anymore ([0015c38](https://github.com/panva/node-oidc-provider/commit/0015c38))

With the sunset of https://rawgit.com i'm not going to look for a replacement CDN that hosts github
content using the right content-type. This addition to sessionManagement is a gimmick helping only
in a small % of cases anyway.

Note: Updates to draft and experimental specification versions are released as MINOR library versions,
if you utilize these specification implementations consider using the tilde `~` operator in your
package.json since breaking changes such as this one may be introduced as part of these version updates.



## [5.1.2](https://github.com/panva/node-oidc-provider/compare/v5.1.0...v5.1.2) (2018-10-23)


### Bug Fixes

* allow http2 req/res in interaction detail helpers (fixes [#383](https://github.com/panva/node-oidc-provider/issues/383)) ([a86aba7](https://github.com/panva/node-oidc-provider/commit/a86aba7))



## [5.1.0](https://github.com/panva/node-oidc-provider/compare/v5.0.1...v5.1.0) (2018-10-03)


### Bug Fixes

* ignore sector_identifier_uri when subject_type is not pairwise ([416e379](https://github.com/panva/node-oidc-provider/commit/416e379))


### Features

* added Resource Indicators for OAuth 2.0 - draft 00 implementation ([1bc2994](https://github.com/panva/node-oidc-provider/commit/1bc2994))



## [5.0.1](https://github.com/panva/node-oidc-provider/compare/v5.0.0...v5.0.1) (2018-09-27)



## [5.0.0](https://github.com/panva/node-oidc-provider/compare/v4.8.3...v5.0.0) (2018-09-26)


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
