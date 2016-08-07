# oidc-provider

[![build][travis-image]][travis-url] [![dependencies][david-image]][david-url] [![codecov][codecov-image]][codecov-url] [![npm][npm-image]][npm-url] [![licence][licence-image]][licence-url]

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
    * [Features](#features)
    * [Routes](#routes)
    * [Certificates](#keys-signing-and-encryption)
    * [Persistance](#persistance)
    * [Accounts](#accounts)
    * [Interaction](#interaction)
    * [Clients](#clients)
    * [Custom Grant Types](#custom-grant-types)
  * [Events](#events)
  * [Certification](#certification)

## Implemented specs & features

The following specifications are implemented by oidc-provider.

- [OpenID Connect Core 1.0 incorporating errata set 1][feature-core]
  - Authorization
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
    - Normal Claims
    - Aggregated Claims
    - Distributed Claims
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
- [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1][feature-registration]
- [OpenID Connect Session Management 1.0 - draft26][feature-session-management]
- [OAuth 2.0 Form Post Response mode][feature-form-post]
- [RFC7009 - OAuth 2.0 Token revocation][feature-revocation]
- [RFC7662 - OAuth 2.0 Token introspection][feature-introspection]

## Get started
To run and experiment with an example server, clone the oidc-provider repo and install the dependencies:

```bash
$ git clone https://github.com/panva/node-oidc-provider.git oidc-provider
$ cd oidc-provider
$ npm install
$ node example
```
Visiting `http://localhost:3000/.well-known/openid-configuration` will help you to discover how the
example is [configured](example).

This example is also deployed and available for you to experiment with [here][heroku-example].
An example client using this provider is available [here][heroku-example-client]
(uses [openid-client][openid-client]).

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

To also enable require_request_uri_registration do this:
```js
const configuration = { features: { requestUri: { requireRequestUriRegistration: true } } };
```

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


**Dynamic registration features**  
```js
const configuration = { features: { registration: Boolean[false] } };
```
Enables features described in [Dynamic Client Registration 1.0][feature-registration].

### Routes
You can change the [default routes](lib/helpers/defaults.js#L72-L82) by providing a routes object
to the oidc-provider constructor.

```js
const oidc = new Provider('http://localhost:3000', {
  routes: {
    authorization: '/authz',
    certificates: '/jwks'
  }
});
```


### Keys (signing and encryption)
To add RSA or EC signing and encryption keys use the `addKey` method on a oidc-provider instance.
This accepts a jwk formatted private key object and returns a Promise, resolved with
[node-jose][node-jose] jose.JWK.Key

At the very least you must add one RSA key (and do yourself a favor and use at least 2048 bit). You
MAY provide the `use` and `kid` properties. When `use` is omitted the key will be available for both
signing and encryption. When `kid` is omitted it will be calculated using
[JSON Web Key (JWK) Thumbprint][feature-thumbprint].


### Persistance
The provided example and any new instance of oidc-provider will use the basic in-memory adapter for
storing issued tokens, codes and user sessions. This is fine for as long as you develop, configure
and generally just play around since every time you restart your process all information will be
lost. As soon as you cannot live with this limitation you will be required to provide an adapter
for oidc-provider to use.

```js
const MyAdapter = require('./my_adapter');
const oidc = new Provider('http://localhost:3000', {
  adapter: MyAdapter
});
```

The API oidc-provider expects is documented [here](example/my_adapter.js). For reference see the
[memory adapter](lib/adapters/memory_adapter.js) and [redis](example/adapters/redis.js) of
[mongodb](example/adapters/mongodb.js) adapters. There's also a simple test
[[redis](example/adapters/redis_test.js),[mongodb](example/adapters/mongodb_test.js)] you can use to
check your own implementation.

### Accounts
oidc-provider needs to be able to find an account and once found the account needs to have an
`accountId` property as well as `claims()` function returning an object with claims that correspond
to the claims your issuer supports. You can make oidc-provider lookup your accounts using your
method during initialization.

```js
const oidc = new Provider('http://localhost:3000', {
  findById: function (id) {
    return Promise.resolve({
      accountId: id,
      claims() { return { sub: id }; },
    });
  }
});
```

Note: the `findById` method needs to be yieldable, returning a Promise is recommended.  
Tip: check how the [example](example/account.js) deals with this

**Aggregated and Distributed claims**  
Returning aggregated and distributed claims is as easy as having your Account#claims method return
the two necessary members `_claim_sources` and `_claim_names` with the
[expected][feature-aggregated-distributed-claims] properties. oidc-provider will include only the
sources for claims that are part of the request scope, omitting the ones that the RP did not request
and leaving out the entire `_claim_sources` and `_claim_sources` if they bear no requested claims.

Note: to make sure the RPs can expect these claims you should configure your discovery to return
the respective claim types via the `claim_types_supported` property.
```js
const oidc = new Provider('http://localhost:3000', {
  discovery: {
    claim_types_supported: ['normal', 'aggregated', 'distributed']
  }
});
```


### Interaction
Since oidc-provider comes with no views and interaction handlers what so ever it's up to you to fill
those in, here's how oidc-provider allows you to do so:

When oidc-provider cannot fulfill the authorization request for any of the possible reasons (missing
user session, requested ACR not fulfilled, prompt requested, ...) it will resolve an `interactionUrl`
(configured during initialization) and redirect the User-Agent to that url. Before doing so it will
create a signed `_grant` cookie that you can read from your interaction 'app'. This
cookie contains 1) details of the interaction that is required; 2) all authorization request
parameters and 3) the uuid of the authorization request and 4) the url to redirect the user to once
interaction is finished. oidc-provider expects that you resolve all future interactions in one go
and only then redirect the User-Agent back with the results.

Once all necessary interaction is finished you are expected to redirect back to the authorization
endpoint, affixed by the uuid of the original request and the interaction results dumped in a signed
`_grant_result` cookie. Please see the [example](example/index.js), it's using a helper `resume` of
the provider instance that ties things together for you.

### Clients
Clients can be managed programmatically or via out of bounds mechanisms using your provided Adapter.
At the very least you must provide client_id, client_secret and redirect_uris for each client. See
the rest of the available metadata [here][client-metadata].

Note: each oidc-provider caches the clients once they are loaded (via either of the mechanisms),
when in need of client configuration "reload" you can purge this cache like so
`oidc.get('Client').purge()`;

**via Provider interface**  
To add pre-established clients use the `addClient` method on a oidc-provider instance. This accepts
metadata object and returns a Promise, fulfilled with the added Client object, rejected with a
validation or other errors that may have been encountered.

```js
const oidc = new Provider('http://localhost:3000');
const metadata = {
  // ...
};
oidc.addClient(metadata).then(fulfillmentHandler, rejectionHandler);
```

**via Adapter**  
Storing client metadata in your storage is recommended for distributed deployments. Also when you
want to provide a client configuration GUI or plan on changing this data often. Clients get loaded
*! and validated !* when they are first needed, any metadata validation error encountered during
this first load will be thrown and handled like any other context specific errors.

### Custom Grant Types
oidc-provider comes with the basic grants implemented, but you can register your own grant types,
for example to implement a [password grant type][password-grant]. You can check the standard
grant factories [here](lib/actions/token).

```js
const parameters = ['username', 'password'];

provider.registerGrantType('password', function passwordGrantTypeFactory(providerInstance) {
  return function * passwordGrantType(next) {
    if (this.oidc.params.username === 'foo' && this.oidc.params.password === 'bar') {
      const AccessToken = providerInstance.get('AccessToken');
      const at = new AccessToken({
        accountId: 'foo',
        clientId: this.oidc.client.clientId,
        grantId: this.oidc.uuid,
      });

      const accessToken = yield at.save();
      const tokenType = 'Bearer';
      const expiresIn = AccessToken.expiresIn;

      this.body = {
        access_token: accessToken,
        expires_in: expiresIn,
        token_type: tokenType,
      };
    } else {
      this.body = {
        error: 'invalid_grant',
        error_description: 'invalid credentials provided',
      };
      this.status = 400;
    }

    yield next;
  };
}, parameters);
```
Tip: you are able to modify the implemented grant type behavior like this.

## Events
The oidc-provider instance is an event emitter, `this` is always the instance. In events where `ctx`(koa
request context) is passed to the listener `ctx.oidc` holds additional details like recognized
parameters, loaded client or session.

**server_error**  
oidc.on(`'server_error', function (error, ctx) { }`)  
Emitted when an exception is thrown or promise rejected from either the Provider or your provided
adapters. If it comes from the library you should probably report it.

**authorization.success**  
oidc.on(`'authorization.success', function (ctx) { }`)  
Emitted with every successful authorization request. Useful i.e. for collecting metrics or
triggering any action you need to execute after succeeded authorization.

**authorization.error**  
oidc.on(`'authorization.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `authorization` endpoint.

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

**registration.error**  
oidc.on(`'registration.error', function (error, ctx) { }`)  
Emitted when a handled error is encountered in the `registration` endpoint.

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
Emitted when a token is issued. All tokens extending `OAuthToken` emit this event.
token can be one of `AccessToken`, `AuthorizationCode`,
`ClientCredentials`, `RefreshToken`.

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
[david-image]: https://img.shields.io/david/panva/node-oidc-provider.svg?style=flat-square&maxAge=7200
[david-url]: https://david-dm.org/panva/node-oidc-provider
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
[feature-registration]: http://openid.net/specs/openid-connect-registration-1_0.html
[feature-session-management]: http://openid.net/specs/openid-connect-session-1_0.html
[feature-form-post]: http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
[feature-revocation]: https://tools.ietf.org/html/rfc7009
[feature-introspection]: https://tools.ietf.org/html/rfc7662
[feature-thumbprint]: https://tools.ietf.org/html/rfc7638
[client-metadata]: http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
[core-claims-url]: http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
[core-jwt-parameters-url]: http://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
[node-jose]: https://github.com/cisco/node-jose
[heroku-example]: https://guarded-cliffs-8635.herokuapp.com/op/.well-known/openid-configuration
[heroku-example-client]: https://tranquil-reef-95185.herokuapp.com/client
[openid-client]: https://github.com/panva/node-openid-client
[password-grant]: https://tools.ietf.org/html/rfc6749#section-4.3
[feature-aggregated-distributed-claims]: http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
