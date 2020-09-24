# oidc-provider

oidc-provider is an OAuth 2.0 Authorization Server with [OpenID Connect][openid-connect] and many
additional features and standards implemented.

**Table of Contents**

- [Implemented specs & features](#implemented-specs--features)
- [Certification](#certification)
- [Get started](#get-started)
- [Documentation & Configuration](#documentation--configuration)
- [Recipes](#recipes)
- [Debugging](#debugging)
- [Events](#events)

## Implemented specs & features

The following specifications are implemented by oidc-provider. Note that not all features are
enabled by default, check the configuration section on how to enable them.

- [RFC6749 - OAuth 2.0][oauth2] & [OpenID Connect Core 1.0][core]
  - Authorization (Authorization Code Flow, Implicit Flow, Hybrid Flow)
  - UserInfo Endpoint and ID Tokens including Signing and Encryption
  - Passing a Request Object by Value or Reference including Signing and Encryption
  - Public and Pairwise Subject Identifier Types
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Client Authentication incl. client_secret_jwt and private_key_jwt methods
- [OpenID Connect Discovery 1.0][discovery]
- [OpenID Connect Dynamic Client Registration 1.0][registration] and [RFC7591 - OAuth 2.0 Dynamic Client Registration Protocol][oauth2-registration]
- [OAuth 2.0 Form Post Response Mode][form-post]
- [RFC7636 - Proof Key for Code Exchange (PKCE)][pkce]
- [RFC7009 - OAuth 2.0 Token Revocation][revocation]
- [RFC7592 - OAuth 2.0 Dynamic Client Registration Management Protocol][registration-management]
- [RFC7662 - OAuth 2.0 Token Introspection][introspection]
- [RFC8252 - OAuth 2.0 for Native Apps BCP (AppAuth)][oauth-native-apps]
- [RFC8628 - OAuth 2.0 Device Authorization Grant (Device Flow)][device-flow]
- [RFC8705 - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens (MTLS)][mtls]

The following draft specifications are implemented by oidc-provider.
- [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens - draft 05][jwt-at]
- [JWT Response for OAuth Token Introspection - draft 09][jwt-introspection]
- [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) - draft 02][jarm]
- [OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (DPoP) - draft 01][dpop]
- [OAuth 2.0 JWT Secured Authorization Request (JAR)][jar]
- [OAuth 2.0 Pushed Authorization Requests - draft 03][par]
- [OAuth 2.0 Resource Indicators - draft 08][resource-indicators]
- [OAuth 2.0 Web Message Response Mode - individual draft 00][wmrm]
- [OpenID Connect RP-Initiated Logout 1.0 - draft 01][rpinitiated-logout]
- [OpenID Connect Back-Channel Logout 1.0 - draft 06][backchannel-logout]
- [OpenID Connect Front-Channel Logout 1.0 - draft 04][frontchannel-logout]
- [OpenID Connect Session Management 1.0 - draft 30][session-management]

Updates to draft specification versions are released as MINOR library versions,
if you utilize these specification implementations consider using the tilde `~` operator in your
package.json since breaking changes may be introduced as part of these version updates. Alternatively
[acknowledge](/docs/README.md#features) the version and be notified of breaking changes as part of
your CI.

## Certification
[<img width="184" height="96" align="right" src="https://cdn.jsdelivr.net/gh/panva/node-oidc-provider@acd3ebf2f5ebbb5605463cb681a1fb2ab9742ace/OpenID_Certified.png" alt="OpenID Certification">][openid-certified-link]  
Filip Skokan has [certified][openid-certified-link] that [oidc-provider][npm-url]
conforms to the following profiles of the OpenID Connect™ protocol

- OP Basic, Implicit, Hybrid, Config, Dynamic, Form Post, and 3rd Party-Init
- OP Front-Channel Logout, Back-Channel Logout, RP-Initiated Logout, and Session Management
- OP FAPI R/W MTLS and Private Key

## Sponsor

[<img width="65" height="65" align="left" src="https://avatars.githubusercontent.com/u/2824157?s=75&v=4" alt="auth0-logo">][sponsor-auth0] If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan at [auth0.com/developers][sponsor-auth0].<br><br>

## Support

If you or your business use oidc-provider, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

## Get started
You may check the [example folder](/example) or follow a [step by step example][example-repo] to see
which of those fits your desired application setup.

A feature-rich example configuration of oidc-provider is available for you to experiment with
[here][heroku-example]. Dynamic Client Registration is open, you can literally register any client
you want there. An example client using this provider is available [here][heroku-example-client]
(uses [openid-client][openid-client]).

Also be sure to check the available configuration docs section.

## [Documentation](/docs/README.md) & Configuration

oidc-provider can be mounted to existing connect, express, fastify, hapi, or koa applications, see
[how](/docs/README.md#mounting-oidc-provider). The provider allows to be extended and configured in
various ways to fit a variety of uses. See the [documentation](/docs/README.md).

```js
const { Provider } = require('oidc-provider');
const configuration = {
  // ... see available options /docs
  clients: [{
    client_id: 'foo',
    client_secret: 'bar',
    redirect_uris: ['http://lvh.me:8080/cb'],
    // + other client properties
  }],
};

const oidc = new Provider('http://localhost:3000', configuration);

// express/nodejs style application callback (req, res, next) for use with express apps, see /examples/express.js
oidc.callback

// koa application for use with koa apps, see /examples/koa.js
oidc.app

// or just expose a server standalone, see /examples/standalone.js
const server = oidc.listen(3000, () => {
  console.log('oidc-provider listening on port 3000, check http://localhost:3000/.well-known/openid-configuration');
});
```


## Recipes
Collection of useful configurations use cases are available over at [recipes](/recipes).


## Debugging
oidc-provider uses the [debug][debug-link] module internally to log information about various states
of authentication requests, errors and grants. To see all these set the `DEBUG` environment variable
to `oidc-provider:*` when launching your app.

There is no filter on what is included in the debug output, since it may end-user Personally
identifiable information or client credentials its use is only advised for debugging, not regular
logging. Use emitted events to cherry pick the one's of interest to your flows and form your own
logs aware of what should and should not be a part of a logged message.


## Events
Your oidc-provider instance is an event emitter, using event handlers you can hook into the various
actions and i.e. emit metrics or that react to specific triggers. In some scenarios you can even
change the defined behavior.  
See the list of available emitted [event names](/docs/events.md) and their description.


[npm-url]: https://www.npmjs.com/package/oidc-provider
[openid-certified-link]: https://openid.net/certification/
[openid-connect]: https://openid.net/connect/
[core]: https://openid.net/specs/openid-connect-core-1_0.html
[discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[oauth2-registration]: https://tools.ietf.org/html/rfc7591
[registration]: https://openid.net/specs/openid-connect-registration-1_0.html
[session-management]: https://openid.net/specs/openid-connect-session-1_0-30.html
[form-post]: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
[oauth2]: https://tools.ietf.org/html/rfc6749
[oauth2-bearer]: https://tools.ietf.org/html/rfc6750
[revocation]: https://tools.ietf.org/html/rfc7009
[introspection]: https://tools.ietf.org/html/rfc7662
[pkce]: https://tools.ietf.org/html/rfc7636
[example-repo]: https://github.com/panva/node-oidc-provider-example
[heroku-example]: https://op.panva.cz/.well-known/openid-configuration
[heroku-example-client]: https://tranquil-reef-95185.herokuapp.com/client
[openid-client]: https://github.com/panva/node-openid-client
[backchannel-logout]: https://openid.net/specs/openid-connect-backchannel-1_0-06.html
[frontchannel-logout]: https://openid.net/specs/openid-connect-frontchannel-1_0-04.html
[registration-management]: https://tools.ietf.org/html/rfc7592
[oauth-native-apps]: https://tools.ietf.org/html/rfc8252
[debug-link]: https://github.com/visionmedia/debug
[wmrm]: https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00
[jar]: https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-26
[device-flow]: https://tools.ietf.org/html/rfc8628
[jwt-introspection]: https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-09
[sponsor-auth0]: https://auth0.com/developers?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=oidc-provider&utm_content=auth
[mtls]: https://tools.ietf.org/html/rfc8705
[dpop]: https://tools.ietf.org/html/draft-ietf-oauth-dpop-01
[resource-indicators]: https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08
[jarm]: https://openid.net/specs/openid-financial-api-jarm-wd-02.html
[jwt-at]: https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-05
[support-sponsor]: https://github.com/sponsors/panva
[par]: https://tools.ietf.org/html/draft-ietf-oauth-par-03
[rpinitiated-logout]: https://openid.net/specs/openid-connect-rpinitiated-1_0-01.html
