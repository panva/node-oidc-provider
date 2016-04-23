oidc-provider
=======

[![Build Status][travis-image]][travis-url]

oidc-provider is an OpenID Provider implementation of [OpenID Connect][openid-connect]. It allows to export a complete Koa.js OpenID Provider implementation which you can mount to your existing Koa.js applications or run standalone. This implementation does not force you into any data models or persistance stores, instead it expects you to provide interfaces. Comes with several example interfaces (in-memory, Redis, MongoDB, API).

The provided examples also implement simple user interaction views but those are not forced on you as they do not come as part of the exported application, instead you are encouraged to implement your own unique-looking and functioning user flows.

## Implemented Specs & Features

The following specifications are implemented by oidc-provider, where it makes sense you can choose to configure them or simply disable them completely if you do not plan to utilize them.

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

## Example
To run and experiment with the example, clone the oidc-provider repo and install the dependencies:

```bash
$ git clone git://github.com/panva/node-oidc-provider.git oidc-provider
$ cd oidc-provider
$ npm install
$ node example
```

## Certification
![openid_certified][openid-certified-logo]

[OpenID Certified™][openid-certified-link] by Filip Skokan to the OP Basic, OP Implicit, OP Hybrid, OP Config and OP Dynamic profiles of the OpenID Connect™ protocol.

## License
[MIT](LICENSE.md)

[travis-image]: https://travis-ci.org/panva/node-oidc-provider.svg?branch=master
[travis-url]: https://travis-ci.org/panva/node-oidc-provider
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
