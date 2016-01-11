node-oidc
=======

node-oidc is an OpenID Provider implementation of [OpenID Connect](http://openid.net/connect/). It allows to export a complete Koa.js OpenID Provider implementation which you can mount to your existing Koa.js applications. This implementation does not force you into any data models or persistance stores, instead it expects you to provide interfaces. Comes with several example interfaces (in-memory, Redis, MongoDB, API).

The provided examples also implement simple user interaction views but those are not forced on you as they do not come as part of the exported application, instead you are encouraged to implement your own unique-looking user flows.

## Implemented Specs & Features

The following specifications are implemented by node-oidc, where it makes sense you can choose to configure them or simply disable them completely if you do not plan to utilize them.

- [OpenID Connect Core 1.0 incorporating errata set 1](http://openid.net/specs/openid-connect-core-1_0.html)
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
- [OpenID Connect Discovery 1.0 incorporating errata set 1](http://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](http://openid.net/specs/openid-connect-registration-1_0.html)
- [OpenID Connect Session Management 1.0 - draft25](http://openid.net/specs/openid-connect-session-1_0.html)
- [OAuth 2.0 Multiple Response Type Encoding Practices](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- [OAuth 2.0 Form Post Response Mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [RFC7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC7638 - JSON Web Key (JWK) Thumbprint](https://tools.ietf.org/html/rfc7638)

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
![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)

[OpenID Certified™](http://openid.net/certification/) by Filip Skokan to the OP Basic, OP Implicit, OP Hybrid, OP Config and OP Dynamic profiles of the OpenID Connect™ protocol.
