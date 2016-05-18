# oidc-provider

[![build][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url] [![npm][npm-image]][npm-url] [![licence][licence-image]][licence-url]

oidc-provider is an OpenID Provider implementation of [OpenID Connect][openid-connect]. It allows to
export a complete Koa.js OpenID Provider implementation which you can mount to your existing Koa.js
applications or run standalone. This implementation does not force you into any data models or
persistance stores, instead it expects you to provide an adapter. A generic in memory adapter is
available to get you started.

The provided examples also implement simple user interaction views but those are not forced on you
as they do not come as part of the exported application, instead you are encouraged to implement
your own unique-looking and functioning user flows.

**Table of Contents**

  * [Implemented specs &amp; features](#implemented-specs--features)
  * [Get started](#get-started)
  * [Configuration](#configuration)
    * [Certificates](#keys-signing-and-encryption)
    * [Clients](#clients)
    * [Features](#features)
    * [Routes](#routes)
    * [Persistance](#persistance)
  * [Events](#events)
  * [Certification](#certification)

## Implemented specs & features

The following specifications are implemented by oidc-provider.

- [OpenID Connect Core 1.0 incorporating errata set 1][feature-core]
  - Authentication
    - Authorization Code Flow
    - Implicit Flow
    - Hybrid Flow
    - proper handling for parameters
      - claims
      - request
      - request_uri
      - acr_values
      - id_token_hint
      - max_age
  - Scopes
  - Claims
    - Standard-defined Claims
    - Custom Claims
  - UserInfo Endpoint including
    - Signing (Asymmetric and Symmetric Signatures)
    - Encryption (RSA, Elliptic Curve)
  - Passing a Request Object by Value or Reference including
    - Signing (Asymmetric and Symmetric Signatures)
    - Encryption (RSA, Elliptic Curve)
  - Subject Identifier Types
    - public
    - pairwise
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Client Authentication
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
    - private_key_jwt
- [OpenID Connect Discovery 1.0 incorporating errata set 1][feature-discovery]
- [OpenID Connect Session Management 1.0 - draft26][feature-session-management]
- [OAuth 2.0 Form Post Response mode][feature-form-post]
- [RFC7009 - OAuth 2.0 Token revocation][feature-revocation]
- [RFC7662 - OAuth 2.0 Token introspection][feature-introspection]

## Get started
To run and experiment with an example client and a server, clone the oidc-provider repo and install
the dependencies:

```bash
$ git clone https://github.com/panva/node-oidc-provider.git oidc-provider
$ cd oidc-provider
$ npm install
$ node example
```

Otherwise just install the package in your app and follow the [example use](example/index.js).
```
$ npm install oidc-provider --save
```

## Configuration
```js
const Provider = require('oidc-provider').Provider;
const issuer = 'http://localhost:3000';
const configuration = {
  // ... see available options below
};

const oidc = new Provider(issuer, configuration);
```
[Default configuration values](lib/helpers/defaults.js).

### Features

**Discovery**  
```js
const configuration = { features: { discovery: Boolean[true] } };
```
Exposes `/.well-known/webfinger` and `/.well-known/openid-configuration` endpoints. Contents of the
latter reflect your actual configuration, i.e. available claims, features and so on.
Note: when using koa-mount to slap the Provider on to an existing application you may want to have
these endpoints relative from your root, to see how (using koa-rewrite) check the
[example](example/index.js).


**Authorization `claims` parameter**  
```js
const configuration = { features: { claimsParameter: Boolean[false] } };
```
Enables the use and validations of `claims` parameter as described in [Core 1.0][core-claims-url]
and the discovery endpoint property `claims_parameter_supported` set to true.

**Token endpoint `client_credentials` grant**  
```js
const configuration = { features: { clientCredentials: Boolean[false] } };
```
Enables `grant_type=client_credentials` to be used on the token endpoint. Note: client still has to
be allowed this grant.  
Hint: allowing this grant together with token introspection and revocation is an easy and elegant
way to allow authorized access to some less sensitive backend actions.

**Encryption features**  
```js
const configuration = { features: { encryption: Boolean[false] } };
```
... userinfo, idtoken and request parameter depending on client configuration


**Refresh tokens for everyone**  
```js
const configuration = { features: { refreshToken: Boolean[false] } };
```
Every grant_type=authorization_code will result in refresh_token being issued (if a client also has
refresh_token part of it's announced `grant_type`s). Also enables the `grant_type=refresh_token` for
these clients.


**Authorization `request` parameter**  
```js
const configuration = { features: { request: Boolean[false] } };
```
Enables the use and validations of `request` parameter as described in
[Core 1.0][core-jwt-parameters-url] and the discovery endpoint property
`request_parameter_supported` set to true.


**Authorization `request_uri` parameter**  
```js
const configuration = { features: { requestUri: Boolean[false] } };
```
Enables the use and validations of `request_uri` parameter as described in
[Core 1.0][core-jwt-parameters-url] and the discovery endpoint property
`request_uri_parameter_supported` set to true.

**Introspection endpoint**  
```js
const configuration = { features: { introspection: Boolean[false] } };
```
Enables the use of Introspection endpoint as described in [RFC7662][feature-introspection] for
tokens of type AccessToken, ClientCredentials and RefreshToken. When enabled
token_introspection_endpoint property of the discovery endpoint is `true`, otherwise the property
is not sent. The use of this endpoint is covered by the same authz mechanism as the regular token
endpoint.


**Revocation endpoint**  
```js
const configuration = { features: { revocation: Boolean[false] } };
```
Enables the use of Revocation endpoint as described in [RFC7009][feature-revocation] for tokens of
type AccessToken, ClientCredentials and RefreshToken. When enabled
token_revocation_endpoint property of the discovery endpoint is `true`, otherwise the property
is not sent. The use of this endpoint is covered by the same authz mechanism as the regular token
endpoint.


**Session management features**  
```js
const configuration = { features: { sessionManagement: Boolean[false] } };
```
Enables features described in [Session Management 1.0 - draft26][feature-session-management].


### Routes
The following are the respective endpoint routes.
```js
const configuration = {  
  routes: {
    authentication: '/auth',
    certificates: '/certs',
    check_session: '/session/check',
    end_session: '/session/end',
    introspection: '/token/introspection',
    revocation: '/token/revocation',
    token: '/token',
    userinfo: '/me',
  }
};
```


### Keys (signing and encryption)
To add RSA or EC signing and encryption keys use the `addKey` method on a Provider instance. This
accepts a jwk formatted private key object and returns a Promise, resolved with
[node-jose][node-jose] jose.JWK.Key

At the very least you must add one RSA key (and do yourself a favor and use at least 2048 bit). You
MAY provide the `use` and `kid` properties. When `use` is ommited the key will be available for both
signing and encryption. When `kid` is ommited it will be calculated according to
[JSON Web Key (JWK) Thumbprint][feature-thumbprint].

### Clients
To add pre-established clients use the `addClient` method on a Provider instance. This accepts a
metadata object and returns a Promise, fulfilled with the Client object, rejected with a validation
or other errors that may have been encountered. At the very least you must provide client_id,
client_secret and redirect_uris. See the rest of the available metadata [here][client-metadata].

```js
const clientMetadata = {
  // ...
};
oidc.addClient(clientMetadata).then(fulfillmentHandler, rejectionHandler);
```


### Persistance

## Events
The Provider instance is an event emitter, `this` is always the instance. In events where `ctx`(koa
request context) is passed to the listener `ctx.oidc` holds additional details like recognized
parameters, loaded client or session.

**server_error**  
oidc.on(`'server_error', function (error, ctx) { }`)  
Emitted when an exception is thrown or promise rejected from either the Provider or your provided
adapters. If it comes from the library you should probably report it.

**authentication.success**  
oidc.on(`'authentication.success', function (ctx) { }`)  
Emitted with every successful authentication request. Useful i.e. for collecting metrics or
triggering any action you need to execute after succeeded authentication.

**authentication.error**  
oidc.on(`'authentication.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `authentication` endpoint.

**grant.success**  
oidc.on(`'grant.success', function (ctx) { }`)  
Emitted with every successful grant request. Useful i.e. for collecting metrics or triggering any
action you need to execute after succeeded grant.

**grant.error**  
oidc.on(`'grant.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `grant` endpoint.

**certificates.error**  
oidc.on(`'certificates.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `certificates` endpoint.

**discovery.error**  
oidc.on(`'discovery.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `discovery` endpoint.

**introspection.error**  
oidc.on(`'introspection.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `introspection` endpoint.

**revocation.error**  
oidc.on(`'revocation.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `revocation` endpoint.

**userinfo.error**  
oidc.on(`'userinfo.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `userinfo` endpoint.

**check_session.error**  
oidc.on(`'check_session.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `check_session` endpoint.

**end_session.error**  
oidc.on(`'end_session.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `end_session` endpoint.

**webfinger.error**  
oidc.on(`'webfinger.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `webfinger` endpoint.

**token.issued**  
oidc.on(`'token.issued', function (token) { }`)  
Emitted when a token is issued. All tokens extending `provider.OAuthToken` emit this event.
token can be one of `provider.AccessToken`, `provider.AuthorizationCode`,
`provider.ClientCredentials`, `provider.RefreshToken`.

**token.consumed**  
oidc.on(`'token.consumed', function (token) { }`)  
Emitted when a token (actually just AuthorizationCode) is used.

**token.revoked**  
oidc.on(`'token.revoked', function (token) { }`)  
Emitted when a token is about to be revoked.

**grant.revoked**  
oidc.on(`'grant.revoked', function (grantId) { }`)  
Emitted when tokens resulting from a single grant are about to be revoked.
`grantId` is uuid formatted string. Use this to cascade the token revocation in cases where your
adapter cannot provides functionality.


## Certification
![openid_certified][openid-certified-logo]

[OpenID Certified™][openid-certified-link] by Filip Skokan to the OP Basic, OP Implicit, OP Hybrid,
OP Config and OP Dynamic profiles of the OpenID Connect™ protocol.

[travis-image]: https://img.shields.io/travis/panva/node-oidc-provider/master.svg?style=flat-square&maxAge=7200
[travis-url]: https://travis-ci.org/panva/node-oidc-provider
[codecov-image]: https://img.shields.io/codecov/c/github/panva/node-oidc-provider/master.svg?style=flat-square&maxAge=7200
[codecov-url]: https://codecov.io/gh/panva/node-oidc-provider
[npm-image]: https://img.shields.io/npm/v/oidc-provider.svg?style=flat-square&maxAge=7200
[npm-url]: https://www.npmjs.com/package/oidc-provider
[licence-image]: https://img.shields.io/github/license/panva/node-oidc-provider.svg?style=flat-square&maxAge=7200
[licence-url]: LICENSE.md
[openid-certified-link]: http://openid.net/certification/
[openid-certified-logo]: https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png
[openid-connect]: http://openid.net/connect/
[feature-core]: http://openid.net/specs/openid-connect-core-1_0.html
[feature-discovery]: http://openid.net/specs/openid-connect-discovery-1_0.html
[feature-session-management]: http://openid.net/specs/openid-connect-session-1_0.html
[feature-form-post]: http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
[feature-revocation]: https://tools.ietf.org/html/rfc7009
[feature-introspection]: https://tools.ietf.org/html/rfc7662
[feature-thumbprint]: https://tools.ietf.org/html/rfc7638
[client-metadata]: http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
[core-claims-url]: http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
[core-jwt-parameters-url]: http://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
[node-jose]: https://github.com/cisco/node-jose
