# oidc-provider [![Build Status][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url]

oidc-provider is an OpenID Provider implementation of [OpenID Connect][openid-connect]. It allows to export a complete Koa.js OpenID Provider implementation which you can mount to your existing Koa.js applications or run standalone. This implementation does not force you into any data models or persistance stores, instead it expects you to provide interfaces. Comes with several example interfaces (in-memory, Redis, MongoDB, API).

The provided examples also implement simple user interaction views but those are not forced on you as they do not come as part of the exported application, instead you are encouraged to implement your own unique-looking and functioning user flows.

Note: The README is a work in progress.

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
To run and experiment with the example, clone the oidc-provider repo and install the dependencies:

```bash
$ git clone git://github.com/panva/node-oidc-provider.git oidc-provider
$ cd oidc-provider
$ npm install
$ node example
```

## Configuration
This is how you configure your provider. blah blah

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
| session management | sessionManagement |  `false` |

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
The Provider instance is an event emitter, the following events are available.

| emitted events | arguments |
| --- | --- |
| `"server_error"` | `(error, ctx)` |
| `"authentication.success"` | `(ctx)` |
| `"authentication.error"` | `(error, ctx)` |
| `"grant.success"` | `(ctx)` |
| `"grant.error"` | `(error, ctx)` |
| `"grant.revoked"` | `(grantId[string])` |
| `"certificates.error"` | `(error, ctx)` |
| `"discovery.error"` | `(error, ctx)` |
| `"introspection.error"` | `(error, ctx)` |
| `"registration.error"` | `(error, ctx)` |
| `"revocation.error"` | `(error, ctx)` |
| `"userinfo.error"` | `(error, ctx)` |
| `"check_session.error"` | `(error, ctx)` |
| `"end_session.error"` | `(error, ctx)` |
| `"webfinger.error"` | `(error, ctx)` |
| `"token.issued"` | `(token[object])` |
| `"token.consumed"` | `(token[object])` |
| `"token.revoked"` | `(token[object])` |

## Certification
![openid_certified][openid-certified-logo]

[OpenID Certified™][openid-certified-link] by Filip Skokan to the OP Basic, OP Implicit, OP Hybrid, OP Config and OP Dynamic profiles of the OpenID Connect™ protocol.

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
