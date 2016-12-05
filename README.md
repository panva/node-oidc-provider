# oidc-provider

[![build][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url] [![npm][npm-image]][npm-url] [![licence][licence-image]][licence-url]

oidc-provider is an OpenID Provider implementation of [OpenID Connect][openid-connect]. It allows to
export a complete mountable or standalone OpenID Provider implementation. This implementation does
not force you into any data models or persistance stores, instead it expects you to provide an
adapter. A generic in memory adapter is available to get you started.

The provided examples also implement simple user interaction views but those are not forced on you
as they do not come as part of the exported application, instead you are encouraged to implement
your own unique-looking and functioning user flows.

**Table of Contents**

<!-- TOC START min:2 max:2 link:true update:true -->
  - [Implemented specs & features](#implemented-specs--features)
  - [Get started](#get-started)
  - [Configuration and Initialization](#configuration-and-initialization)
  - [Events](#events)
  - [Certification](#certification)

<!-- TOC END -->

## Implemented specs & features

The following specifications are implemented by oidc-provider. Note that not all features are
enabled by default, check the configuration section on how to enable them.

- [OpenID Connect Core 1.0 incorporating errata set 1][feature-core]
  - Authorization (Authorization Code Flow, Implicit Flow, Hybrid Flow)
  - UserInfo Endpoint and ID Tokens including
    - Signing - Asymmetric and Symmetric
    - Encryption - Asymmetric and Symmetric
  - Passing a Request Object by Value or Reference including
    - Signing - Asymmetric and Symmetric
    - Encryption - Asymmetric using RSA or Elliptic Curve
  - Public and Pairwise Subject Identifier Types
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Client Authentication via (client_secret_basic, client_secret_post, client_secret_jwt or private_key_jwt)
- [OpenID Connect Discovery 1.0 incorporating errata set 1][feature-discovery]
- [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1][feature-registration]
- [OAuth 2.0 Form Post Response mode][feature-form-post]
- [RFC7636 - Proof Key for Code Exchange by OAuth Public Clients][feature-pixy]
- [RFC7009 - OAuth 2.0 Token revocation][feature-revocation]
- [RFC7662 - OAuth 2.0 Token introspection][feature-introspection]

The following drafts/experimental specifications are implemented by oidc-provider.
- [OpenID Connect Session Management 1.0 - draft 27][feature-session-management]
- [OpenID Connect Back-Channel Logout 1.0 - draft 03][feature-backchannel-logout]
- [RFC7592 - OAuth 2.0 Dynamic Client Registration Management Protocol (Update and Delete)][feature-registration-management]
- [OAuth 2.0 for Native Apps - draft 06][feature-oauth-native-apps]

Updates to drafts and experimental specification versions are released as MINOR library versions.

## Get started
To run and experiment with an example server, clone the oidc-provider repo and install the dependencies:

```bash
$ git clone https://github.com/panva/node-oidc-provider.git oidc-provider
$ cd oidc-provider
$ npm install
$ node example
```
Visiting `http://localhost:3000/.well-known/openid-configuration` will help you to discover how the
example is [configured](/example).

This example is also deployed and available for you to experiment with [here][heroku-example].
An example client using this provider is available [here][heroku-example-client]
(uses [openid-client][openid-client]).

Otherwise just install the package in your app and follow the [example use](/example/index.js).
It is easy to use with [express](/example/express.js) too.
```
$ npm install oidc-provider --save
```

### 1.0.0 Notice
Migrating from 0.11.x release? Quite a bit has changed along the way to end up with a stable and
sustainable API, see the [CHANGELOG](/CHANGELOG.md#version-100) for list of changes and how to
change your existing 0.11 providers to 1.0

## Configuration and Initialization
oidc-provider allows to be extended and configured in various ways to fit a variety of uses. See
the [available configuration](/docs/configuration.md).

```js
const Provider = require('oidc-provider').Provider;
const issuer = 'http://localhost:3000';
const configuration = {
  // ... see available options /docs/configuration.md
};
const clients = [  ];

const oidc = new Provider(issuer, configuration);
oidc.initialize({ clients }).then(function () {
  console.log(oidc.callback); // => express/nodejs style application callback (req, res)
  console.log(oidc.app); // => koa1.x application
});
```

## Events
Your oidc-provider instance is an event emitter, using event handlers you can hook into the various
actions and i.e. emit metrics or that react to specific triggers. In some scenarios you can even
change the defined behavior.  
See the list of available emitted [event names](/docs/events.md) and their description.

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
[feature-registration]: http://openid.net/specs/openid-connect-registration-1_0.html
[feature-session-management]: http://openid.net/specs/openid-connect-session-1_0-27.html
[feature-form-post]: http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
[feature-revocation]: https://tools.ietf.org/html/rfc7009
[feature-introspection]: https://tools.ietf.org/html/rfc7662
[feature-thumbprint]: https://tools.ietf.org/html/rfc7638
[feature-pixy]: https://tools.ietf.org/html/rfc7636
[node-jose]: https://github.com/cisco/node-jose
[heroku-example]: https://guarded-cliffs-8635.herokuapp.com/op/.well-known/openid-configuration
[heroku-example-client]: https://tranquil-reef-95185.herokuapp.com/client
[openid-client]: https://github.com/panva/node-openid-client
[feature-backchannel-logout]: http://openid.net/specs/openid-connect-backchannel-1_0-03.html
[feature-registration-management]: https://tools.ietf.org/html/rfc7592
[feature-oauth-native-apps]: https://tools.ietf.org/html/draft-ietf-oauth-native-apps-06
