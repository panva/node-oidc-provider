# oidc-provider

[![build][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url]

oidc-provider is an OpenID Provider implementation of [OpenID Connect][openid-connect]. It allows to
export a complete mountable or standalone OpenID Provider implementation. This implementation does
not dictate a fixed data model or persistence store, instead, you must provide adapters for these.
A generic in-memory adapter is available to get you started as well as feature-less dev-only views
to be able to get off the ground.

## v6.0.0 alpha notice

v6.0.0-alpha.x is now available on npm and master branch, please head over to
[#419](https://github.com/panva/node-oidc-provider/issues/419) to provide feedback.

I'm looking for early adopter feedback and pointers to missing
[changelog](https://github.com/panva/node-oidc-provider/blob/master/CHANGELOG.md) entries as well as
misunderstood changes. Throughout the v6.0.0 prerelease line the
[changelog](https://github.com/panva/node-oidc-provider/blob/master/CHANGELOG.md) will be extended and
especially interaction documentation will be provided.

The minimal node version for this alpha is v12.0.0 and v6.0.0 will release as stable sometime after
v12.0.0 lands in April 2019.
**WARNING: Node.js 12 or higher is required for oidc-provider@6 and above.** For older Node.js
versions use [oidc-provider@5](https://github.com/panva/node-oidc-provider/tree/v5.x).

```console
npm i oidc-provider@alpha
```

See [v5.x](https://github.com/panva/node-oidc-provider/tree/v5.x) for the last v5.x release and docs.

**Table of Contents**

- [Implemented specs & features](#implemented-specs--features)
- [Certification](#certification)
- [Get started](#get-started)
- [Configuration](#configuration)
- [Recipes](#recipes)
- [Debugging](#debugging)
- [Events](#events)

## Implemented specs & features

The following specifications are implemented by oidc-provider. Note that not all features are
enabled by default, check the configuration section on how to enable them.

- [OpenID Connect Core 1.0][core]
  - Authorization (Authorization Code Flow, Implicit Flow, Hybrid Flow)
  - UserInfo Endpoint and ID Tokens including Signing and Encryption
  - Passing a Request Object by Value or Reference including Signing and Encryption
  - Public and Pairwise Subject Identifier Types
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Client Authentication incl. client_secret_jwt and private_key_jwt methods
- [OpenID Connect Discovery 1.0][discovery]
- [OpenID Connect Dynamic Client Registration 1.0][registration]
- [OAuth 2.0 Form Post Response Mode][form-post]
- [RFC7636 - Proof Key for Code Exchange by OAuth Public Clients][pkce]
- [RFC7009 - OAuth 2.0 Token Revocation][revocation]
- [RFC7662 - OAuth 2.0 Token Introspection][introspection]
- [RFC8252 - OAuth 2.0 for Native Apps BCP][oauth-native-apps]

The following drafts/experimental specifications are implemented by oidc-provider.
- [JWT Response for OAuth Token Introspection - draft 03][jwt-introspection]
- [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) - draft 02][jarm]
- [OAuth 2.0 Device Authorization Grant - draft 15][device-flow]
- [OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens - draft 12][mtls]
- [OAuth 2.0 Resource Indicators - draft 02][resource-indicators]
- [OAuth 2.0 Web Message Response Mode - draft 00][wmrm]
- [OpenID Connect Back-Channel Logout 1.0 - draft 04][backchannel-logout]
- [OpenID Connect Front-Channel Logout 1.0 - draft 02][frontchannel-logout]
- [OpenID Connect Session Management 1.0 - draft 28][session-management]
- [RFC7592 - OAuth 2.0 Dynamic Client Registration Management Protocol (Update and Delete)][registration-management]

Updates to draft and experimental specification versions are released as MINOR library versions,
if you utilize these specification implementations consider using the tilde `~` operator in your
package.json since breaking changes may be introduced as part of these version updates. Alternatively
[acknowledge](https://github.com/panva/node-oidc-provider/tree/master/docs/README.md#features) the version and
be notified of breaking changes as part of your CI.

Missing a feature? - If it wasn't already discussed before, [ask for it][suggest-feature].  
Found a bug? - [report it][bug].

## Certification
[<img width="184" height="96" align="right" src="https://cdn.jsdelivr.net/gh/panva/node-oidc-provider@acd3ebf2f5ebbb5605463cb681a1fb2ab9742ace/OpenID_Certified.png" alt="OpenID Certification">][openid-certified-link]  
Filip Skokan has [certified][openid-certified-link] that [oidc-provider][npm-url]
conforms to the OP Basic, OP Implicit, OP Hybrid, OP Config, OP Dynamic and OP Form Post profiles
of the OpenID Connect™ protocol.

[![build][conformance-image]][conformance-url]


## Sponsor

[<img width="65" height="65" align="left" src="https://avatars.githubusercontent.com/u/2824157?s=75&v=4" alt="auth0-logo">][sponsor-auth0] If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan at [auth0.com/overview][sponsor-auth0].<br><br>

## Support

[<img src="https://c5.patreon.com/external/logo/become_a_patron_button@2x.png" width="160" align="right">][support-patreon]
If you or your business use oidc-provider, please consider becoming a [Patron][support-patreon] so I can continue maintaining it and adding new features carefree. You may also donate one-time via [PayPal][support-paypal].
[<img src="https://cdn.jsdelivr.net/gh/gregoiresgt/payment-icons@183140a5ff8f39b5a19d59ebeb2c77f03c3a24d3/Assets/Payment/PayPal/Paypal@2x.png" width="100" align="right">][support-paypal]

## Get started
You may check the [example folder](/example) or follow a [step by step example][example-repo] to see
which of those fits your desired application setup.

A feature-rich example configuration of oidc-provider is available for you to experiment with
[here][heroku-example]. Dynamic Client Registration is open, you can literally register any client
you want there. An example client using this provider is available [here][heroku-example-client]
(uses [openid-client][openid-client]).

Also be sure to check the available configuration docs section.


## Configuration
oidc-provider allows to be extended and configured in various ways to fit a variety of uses. See
the [available configuration](/docs/README.md).

```js
const Provider = require('oidc-provider');
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


[travis-image]: https://api.travis-ci.com/panva/node-oidc-provider.svg?branch=master
[travis-url]: https://travis-ci.com/panva/node-oidc-provider
[conformance-image]: https://api.travis-ci.com/panva/oidc-provider-conformance-tests.svg?branch=master
[conformance-url]: https://github.com/panva/oidc-provider-conformance-tests
[codecov-image]: https://img.shields.io/codecov/c/github/panva/node-oidc-provider/master.svg
[codecov-url]: https://codecov.io/gh/panva/node-oidc-provider
[npm-url]: https://www.npmjs.com/package/oidc-provider
[openid-certified-link]: https://openid.net/certification/
[openid-connect]: https://openid.net/connect/
[core]: https://openid.net/specs/openid-connect-core-1_0.html
[discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[registration]: https://openid.net/specs/openid-connect-registration-1_0.html
[session-management]: https://openid.net/specs/openid-connect-session-1_0-28.html
[form-post]: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
[revocation]: https://tools.ietf.org/html/rfc7009
[introspection]: https://tools.ietf.org/html/rfc7662
[pkce]: https://tools.ietf.org/html/rfc7636
[example-repo]: https://github.com/panva/node-oidc-provider-example
[heroku-example]: https://op.panva.cz/.well-known/openid-configuration
[heroku-example-client]: https://tranquil-reef-95185.herokuapp.com/client
[openid-client]: https://github.com/panva/node-openid-client
[backchannel-logout]: https://openid.net/specs/openid-connect-backchannel-1_0-04.html
[frontchannel-logout]: https://openid.net/specs/openid-connect-frontchannel-1_0-02.html
[registration-management]: https://tools.ietf.org/html/rfc7592
[oauth-native-apps]: https://tools.ietf.org/html/rfc8252
[debug-link]: https://github.com/visionmedia/debug
[wmrm]: https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00
[device-flow]: https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15
[jwt-introspection]: https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-03
[sponsor-auth0]: https://auth0.com/overview?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=oidc-provider&utm_content=auth
[suggest-feature]: https://github.com/panva/node-oidc-provider/issues/new?template=feature-request.md
[bug]: https://github.com/panva/node-oidc-provider/issues/new?template=bug-report.md
[mtls]: https://tools.ietf.org/html/draft-ietf-oauth-mtls-14
[resource-indicators]: https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-02
[jarm]: https://openid.net/specs/openid-financial-api-jarm-wd-02.html
[support-patreon]: https://www.patreon.com/panva
[support-paypal]: https://www.paypal.me/panva
