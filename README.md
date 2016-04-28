# oidc-provider [![Build Status][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url]

oidc-provider is an OpenID Provider implementation of [OpenID Connect][openid-connect]. It allows to
export a complete Koa.js OpenID Provider implementation which you can mount to your existing Koa.js
applications or run standalone. This implementation does not force you into any data models or
persistance stores, instead it expects you to provide an adapter. Several generic adapters (i.e.
in-memory, Redis, MongoDB) are available to get you started faster.

The provided examples also implement simple user interaction views but those are not forced on you
as they do not come as part of the exported application, instead you are encouraged to implement
your own unique-looking and functioning user flows.

Note: The README is a work in progress.

**Table of Contents**

  * [Implemented Specs &amp; Features](#implemented-specs--features)
  * [Example](#example)
  * [Configuration](#configuration)
  * [Events](#events)
  * [Certification](#certification)
  * [License](#license)

## Implemented Specs & Features

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
- [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1][feature-registration]
- [OpenID Connect Session Management 1.0 - draft25][feature-session-management]
- [OAuth 2.0 Form Post Response mode][feature-form-post]
- [RFC7009 - OAuth 2.0 Token revocation][feature-revocation]
- [RFC7662 - OAuth 2.0 Token introspection][feature-introspection]
- [RFC7638 - JSON Web Key (JWK) thumbprint][feature-thumbprint]

## Example
To run and experiment with an example client and a server, clone the oidc-provider repo and install
the dependencies:

```bash
$ git clone git://github.com/panva/node-oidc-provider.git oidc-provider
$ cd oidc-provider
$ npm install
$ node example
```

## Configuration


### Enabling features
| feature | option name | short description | default option value |
| --- | --- | --- | --- |
| discovery | discovery | enables the `.well-known` routes | `true` |
| claims parameter | claimsParameter | enables `claims` authentication parameter | `false` |
| client credentials | clientCredentials | enables the `client_credentials` grant on the token endpoint | `false` |
| encryption | encryption | enables ID Token, UserInfo and Request encryption | `false` |
| refresh token | refreshToken | enables the `refresh_token` grant on the token endpoint and makes the OP return refresh_token with every `authorization_code` grant too | `false` |
| registration | registration | `TODO` | `false` |
| request | request | enables `request` authentication parameter | `false` |
| request uri | requestUri | enables `request_uri` authentication parameter | `false` |
| introspection | introspection | enables the introspection route | `false` |
| revocation | revocation | enables the revocation route | `false` |
| session management | sessionManagement | enables session management features | `false` |

### Default routes
The following are the respective endpoint routes.
```json5
routes: {
  authentication: '/auth',
  certificates: '/certs',
  check_session: '/session/check',
  end_session: '/session/end',
  introspection: '/token/introspection',
  registration: '/reg',
  revocation: '/token/revocation',
  token: '/token',
  userinfo: '/me',
}
```

### Persistance adapter

### Configuring ...
interactionPath
renderError
uniqueness

## Events
The Provider instance is an event emitter, `this` is always the instance. In events where `ctx`(koa
request context) is emitted `ctx.oidc` holds additional details like recognized parameters, loaded
client or session.

### Event: 'server_error'
`function (error, ctx) { }`  
Emitted when an exception is thrown or promise rejected from either the Provider or your provided
adapters. If it comes from the library you should probably report it.

### Event: 'authentication.success'
`function (ctx) { }`  
Emitted with every successful authentication request. Useful i.e. for collecting metrics or
triggering any action you need to execute after succeeded authentication.

### Event: 'authentication.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `authentication` endpoint.

### Event: 'grant.success'
`function (ctx) { }`  
Emitted with every successful grant request. Useful i.e. for collecting metrics or triggering any
action you need to execute after succeeded grant.

### Event: 'grant.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `grant` endpoint.

### Event: 'certificates.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `certificates` endpoint.

### Event: 'discovery.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `discovery` endpoint.

### Event: 'introspection.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `introspection` endpoint.

### Event: 'registration.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `registration` endpoint.

### Event: 'revocation.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `revocation` endpoint.

### Event: 'userinfo.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `userinfo` endpoint.

### Event: 'check_session.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `check_session` endpoint.

### Event: 'end_session.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `end_session` endpoint.

### Event: 'webfinger.error'
`function (error, ctx) { }`  
Emitted when a handled error is encountered in the `webfinger` endpoint.

### Event: 'token.issued'
`function (token) { }`  
Emitted when a token is issued. All tokens extending `provider.OAuthToken` emit this event.
token can be one of `provider.AccessToken`, `provider.AuthorizationCode`,
`provider.ClientCredentials`, `provider.RefreshToken`.

### Event: 'token.consumed'
`function (token) { }`  
Emitted when a token (actually just AuthorizationCode) is used.

### Event: 'token.revoked'
`function (token) { }`  
Emitted when a token is about to be revoked.

### Event: 'grant.revoked'
`function (grantId) { }`  
Emitted when tokens resulting from a single grant are about to be revoked.
`grantId` is uuid formatted string. Use this to cascade the token revocation in cases where your
adapter cannot provides functionality.


## Certification
![openid_certified][openid-certified-logo]

[OpenID Certified™][openid-certified-link] by Filip Skokan to the OP Basic, OP Implicit, OP Hybrid,
OP Config and OP Dynamic profiles of the OpenID Connect™ protocol.

## License
[MIT](LICENSE.md)

[travis-image]: https://travis-ci.org/panva/node-oidc-provider.svg?branch=master
[travis-url]: https://travis-ci.org/panva/node-oidc-provider
[codecov-image]: https://codecov.io/gh/panva/node-oidc-provider/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/panva/node-oidc-provider
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
