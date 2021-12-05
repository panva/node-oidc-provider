# oidc-provider

oidc-provider is an OAuth 2.0 Authorization Server with [OpenID Connect][openid-connect] and many
additional features and standards implemented.

**Table of Contents**

- [Implemented specs & features](#implemented-specs--features)
- [Certification](#certification)
- [Get started](#get-started)
- [Documentation & Configuration](#documentation--configuration)
- [Recipes](#recipes)
- [Events](#events)

## Implemented specs & features

The following specifications are implemented by oidc-provider:

_Note that not all features are enabled by default, check the configuration section on how to enable them._

- [RFC6749 - OAuth 2.0][oauth2] & [OpenID Connect Core 1.0][core]
- [OpenID Connect Discovery 1.0][discovery]
- [OpenID Connect Dynamic Client Registration 1.0][registration] and [RFC7591 - OAuth 2.0 Dynamic Client Registration Protocol][oauth2-registration]
- [OAuth 2.0 Form Post Response Mode][form-post]
- [RFC7009 - OAuth 2.0 Token Revocation][revocation]
- [RFC7592 - OAuth 2.0 Dynamic Client Registration Management Protocol][registration-management]
- [RFC7636 - Proof Key for Code Exchange (PKCE)][pkce]
- [RFC7662 - OAuth 2.0 Token Introspection][introspection]
- [RFC8252 - OAuth 2.0 for Native Apps BCP (AppAuth)][oauth-native-apps]
- [RFC8628 - OAuth 2.0 Device Authorization Grant (Device Flow)][device-flow]
- [RFC8705 - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens (MTLS)][mtls]
- [RFC8707 - OAuth 2.0 Resource Indicators][resource-indicators]
- [RFC9101 - OAuth 2.0 JWT-Secured Authorization Request (JAR)][jar]
- [RFC9126 - OAuth 2.0 Pushed Authorization Requests (PAR) - draft 08][par]
- [Financial-grade API Security Profile 1.0 - Part 2: Advanced (FAPI)][fapi]
- [OpenID Connect Client Initiated Backchannel Authentication Flow - Core 1.0 (CIBA)][ciba]

Supported Access Token formats:

- Opaque
- [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens][jwt-at]
- [Platform-Agnostic Security Tokens (PASETO)][paseto-at]

The following draft specifications are implemented by oidc-provider:

- [JWT Response for OAuth Token Introspection - draft 10][jwt-introspection]
- [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) - Implementer's Draft 01][jarm]
- [Financial-grade API: Client Initiated Backchannel Authentication Profile (FAPI-CIBA) - Implementer's Draft 01][fapi-ciba]
- [OAuth 2.0 Authorization Server Issuer Identifier in Authorization Response - draft 04][iss-auth-resp]
- [OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (DPoP) - draft 03][dpop]
- [OpenID Connect Back-Channel Logout 1.0 - draft 06][backchannel-logout]
- [OpenID Connect RP-Initiated Logout 1.0 - draft 01][rpinitiated-logout]

Updates to draft specification versions are released as MINOR library versions,
if you utilize these specification implementations consider using the tilde `~` operator in your
package.json since breaking changes may be introduced as part of these version updates. Alternatively
[acknowledge](/docs/README.md#features) the version and be notified of breaking changes as part of
your CI.

## Certification
[<img width="184" height="96" align="right" src="https://cdn.jsdelivr.net/gh/panva/node-oidc-provider@acd3ebf2f5ebbb5605463cb681a1fb2ab9742ace/OpenID_Certified.png" alt="OpenID Certification">][openid-certified-link]  
Filip Skokan has [certified][openid-certified-link] that [oidc-provider][npm-url]
conforms to the following profiles of the OpenID Connect™ protocol

- Basic OP, Implicit OP, Hybrid OP, Config OP, Dynamic OP, Form Post OP, 3rd Party-Init OP
- Back-Channel OP, RP-Initiated OP
- FAPI 1.0 Advanced Final (w/ Private Key JWT, MTLS, JARM, PAR)
- FAPI 1.0 Second Implementer's Draft (w/ Private Key JWT, MTLS, PAR)
- FAPI-CIBA OP (w/ Private Key JWT, MTLS, Ping mode, Poll mode)

## Sponsor

[<img height="65" align="left" src="https://cdn.auth0.com/blog/github-sponsorships/brand-evolution-logo-Auth0-horizontal-Indigo.png" alt="auth0-logo">][sponsor-auth0] If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan. [Create an Auth0 account; it's free!][sponsor-auth0]<br><br>

## Support

If you or your business use oidc-provider, or you need help using/upgrading the module, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree. The only way to guarantee you get feedback from the author & sole maintainer of this module is to support the package through GitHub Sponsors.

## Get started
You may check the [example folder](/example) or follow a [step by step example][example-repo] to see
which of those fits your desired application setup.

Also be sure to check the available configuration docs section.

## [Documentation](/docs/README.md) & Configuration

oidc-provider can be mounted to existing connect, express, fastify, hapi, or koa applications, see
[how](/docs/README.md#mounting-oidc-provider). The provider allows to be extended and configured in
various ways to fit a variety of uses. See the [documentation](/docs/README.md).

```js
const { Provider } = require('oidc-provider');
const configuration = {
  // ... see /docs for available configuration
  clients: [{
    client_id: 'foo',
    client_secret: 'bar',
    redirect_uris: ['http://lvh.me:8080/cb'],
    // ... other client properties
  }],
};

const oidc = new Provider('http://localhost:3000', configuration);

oidc.listen(3000, () => {
  console.log('oidc-provider listening on port 3000, check http://localhost:3000/.well-known/openid-configuration');
});
```


## Recipes
Collection of useful configurations use cases are available over at [recipes](/recipes).


## Events
oidc-provider instances are event emitters, using event handlers you can hook into the various
actions and i.e. emit metrics that react to specific triggers. See the list of available emitted [event names](/docs/events.md) and their description.


[npm-url]: https://www.npmjs.com/package/oidc-provider
[openid-certified-link]: https://openid.net/certification/
[openid-connect]: https://openid.net/connect/
[core]: https://openid.net/specs/openid-connect-core-1_0.html
[discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[oauth2-registration]: https://tools.ietf.org/html/rfc7591
[registration]: https://openid.net/specs/openid-connect-registration-1_0.html
[form-post]: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
[oauth2]: https://tools.ietf.org/html/rfc6749
[oauth2-bearer]: https://tools.ietf.org/html/rfc6750
[revocation]: https://tools.ietf.org/html/rfc7009
[introspection]: https://tools.ietf.org/html/rfc7662
[pkce]: https://tools.ietf.org/html/rfc7636
[example-repo]: https://github.com/panva/node-oidc-provider-example
[backchannel-logout]: https://openid.net/specs/openid-connect-backchannel-1_0-06.html
[registration-management]: https://tools.ietf.org/html/rfc7592
[oauth-native-apps]: https://tools.ietf.org/html/rfc8252
[jar]: https://www.rfc-editor.org/rfc/rfc9101.html
[device-flow]: https://tools.ietf.org/html/rfc8628
[jwt-introspection]: https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-10
[sponsor-auth0]: https://a0.to/try-auth0
[mtls]: https://tools.ietf.org/html/rfc8705
[dpop]: https://tools.ietf.org/html/draft-ietf-oauth-dpop-03
[resource-indicators]: https://tools.ietf.org/html/rfc8707
[jarm]: https://openid.net/specs/openid-financial-api-jarm-ID1.html
[jwt-at]: https://www.rfc-editor.org/rfc/rfc9068.html
[paseto-at]: https://paseto.io
[support-sponsor]: https://github.com/sponsors/panva
[par]: https://www.rfc-editor.org/rfc/rfc9126.html
[rpinitiated-logout]: https://openid.net/specs/openid-connect-rpinitiated-1_0-01.html
[iss-auth-resp]: https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp-04
[fapi]: https://openid.net/specs/openid-financial-api-part-2-1_0.html
[ciba]: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html
[fapi-ciba]: https://openid.net/specs/openid-financial-api-ciba-ID1.html
