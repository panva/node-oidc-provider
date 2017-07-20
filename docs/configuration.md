# Configuration

oidc-provider allows to be extended and configured in various ways to fit a variety of uses. You
SHOULD tell your instance how to find your user accounts, where to store and retrieve persisted data
from and where your user-interaction happens. The [example](/example) application is a good starting
point to get an idea of what you should provide.

**Table of Contents**

<!-- TOC START min:2 max:2 link:true update:true -->
  - [Default configuration values](#default-configuration-values)
  - [Accounts](#accounts)
  - [Clients](#clients)
  - [Certificates](#certificates)
  - [Configuring available claims](#configuring-available-claims)
  - [Configuring available scopes](#configuring-available-scopes)
  - [Persistence](#persistence)
  - [Interaction](#interaction)
  - [Enable/Disable optional oidc-provider features](#enabledisable-optional-oidc-provider-features)
  - [Custom Grant Types](#custom-grant-types)
  - [Extending Authorization with Custom Parameters](#extending-authorization-with-custom-parameters)
  - [Extending Discovery with Custom Properties](#extending-discovery-with-custom-properties)
  - [Configuring Routes](#configuring-routes)
  - [Fine-tuning supported algorithms](#fine-tuning-supported-algorithms)
  - [Changing HTTP Request Defaults](#changing-http-request-defaults)
  - [Authentication Context Class Reference](#authentication-context-class-reference)
  - [Mounting oidc-provider](#mounting-oidc-provider)
  - [Trusting ssl offloading proxies](#trusting-ssl-offloading-proxies)

<!-- TOC END -->

## Default configuration values
Default values are available for all configuration options.
[Default configuration][defaults] provides details on what the options mean and
what part of the OP they affect.


## Accounts
oidc-provider needs to be able to find an account and once found the account needs to have an
`accountId` property as well as `claims()` function returning an object with claims that correspond
to the claims your issuer supports. Tell oidc-provider how to find your account by an ID.  
`#claims()` can also return a Promise later resolved / rejected.

```js
const oidc = new Provider('http://localhost:3000', {
  async findById(ctx, id) {
    return {
      accountId: id,
      async claims() { return { sub: id }; },
    };
  }
});
```

**Aggregated and Distributed claims**  
Returning aggregated and distributed claims is as easy as having your Account#claims method return
the two necessary members `_claim_sources` and `_claim_names` with the
[expected][aggregated-distributed-claims] properties. oidc-provider will include only the
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


## Clients
Clients can be passed to your provider instance during the `initialize` call or left to be loaded
via your provided Adapter. oidc-provider will use the adapter's `find` method when a non-cached
client_id is encountered. If you only wish to support clients that are initialized and no dynamic
registration then make it so that your adapter resolves client find calls with a falsy value. (e.g.
`return Promise.resolve()`).  

Available [Client Metadata][client-metadata] is validated as defined by the specifications.

Note: each oidc-provider caches the clients once they are loaded. When your adapter-stored client
configuration changes you should either reload your processes or trigger a cache clear
(`provider.Client.cacheClear()`).

**via Provider interface**  
To add pre-established clients use the `initialize` method on a oidc-provider instance. This accepts
a clients array with metadata objects and rejects when the client metadata would be invalid.

```js
const oidc = new Provider('http://localhost:3000');
const clients = [
  {
    token_endpoint_auth_method: 'none',
    client_id: 'mywebsite',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
  {
    // ...
  },
];

oidc.initialize({ clients }).then(fulfillmentHandler, rejectionHandler);
```

**via Adapter**  
Storing client metadata in your storage is recommended for distributed deployments. Also when you
want to provide a client configuration GUI or plan on changing this data often. Clients get loaded
*! and validated !* when they are first needed, any metadata validation error encountered during
this first load will be thrown and handled like any other context specific errors.

Note: Make sure your adapter returns an object with the correct property value types as if they were
submitted via dynamic registration.


## Certificates
See [Certificates](/docs/keystores.md).


## Configuring available claims
The `claims` configuration parameter can be used to define which claims fall under what scope
as well as to expose additional claims that are available to RPs via the claims authorization
parameter. The configuration value uses the following scheme:

```js
new Provider('http://localhost:3000', {
  claims: {
    [scope name]: ['claim name', 'claim name'],
    // or
    [scope name]: {
      [claim name]: null,
    },
    // or (for standalone claims) - only requestable via claims parameter
    //   (when features.claimsParameter is true)
    [standalone claim name]: null
  }
});
```

To follow the [Core-defined scope-to-claim mapping][core-account-claims] use:

```js
new Provider('http://localhost:3000', {
  claims: {
    address: ['address'],
    email: ['email', 'email_verified'],
    phone: ['phone_number', 'phone_number_verified'],
    profile: ['birthdate', 'family_name', 'gender', 'given_name', 'locale', 'middle_name', 'name',
      'nickname', 'picture', 'preferred_username', 'profile', 'updated_at', 'website', 'zoneinfo'],
  },
});
```

## Configuring available scopes
Use the `scopes` configuration parameter to extend or reduce the default scope names that are
available. This list is extended by all scope names detected in the claims parameter as well.
The parameter accepts an array of scope names.

## Persistence
The provided example and any new instance of oidc-provider will use the basic in-memory adapter for
storing issued tokens, codes, user sessions and dynamically registered clients. This is fine for as
long as you develop, configure and generally just play around since every time you restart your
process all information will be lost. As soon as you cannot live with this limitation you will be
required to provide an adapter constructor for oidc-provider to use. This constructor will be called
for every model accessed the first time it is needed. A static `connect` method is called if
present during the initialize phase.

```js
const MyAdapter = require('./my_adapter');
const oidc = new Provider('http://localhost:3000');
oidc.initialize({
  adapter: MyAdapter
});
```

The API oidc-provider expects is documented [here](/example/my_adapter.js). For reference see the
[memory adapter](/lib/adapters/memory_adapter.js) and [redis](/example/adapters/redis.js) or
[mongodb](/example/adapters/mongodb.js) adapters. There's also a simple test
[[redis](/example/adapters/redis_test.js),[mongodb](/example/adapters/mongodb_test.js)] you can use to
check your own implementation.


## Interaction
Since oidc-provider only comes with feature-less views and interaction handlers it's up to you to fill
those in, here is how oidc-provider allows you to do so:

When oidc-provider cannot fulfill the authorization request for any of the possible reasons (missing
user session, requested ACR not fulfilled, prompt requested, ...) it will resolve an `interactionUrl`
(configurable) and redirect the User-Agent to that url. Before doing so it will save a short-lived
session and its identifier dumped into a cookie scoped to the resolved interaction path.

This session contains:

- details of the interaction that is required
- all authorization request parameters
- the uuid of the authorization request
- the url to redirect the user to once interaction is finished

oidc-provider expects that you resolve all future interactions in one go and only then redirect the
User-Agent back with the results

Once the required interactions are finished you are expected to redirect back to the authorization
endpoint, affixed by the uuid of the original request and the interaction results stored in the
interaction session object.

The Provider instance comes with helpers that aid with getting interaction details as well as
packing the results. See them used in the [step-by-step](https://github.com/panva/node-oidc-provider-example)
or [in-repo](/example/index.js) examples.


**Provider#interactionDetails**
```js
// with express
expressApp.get('/interaction/:grant', async (req, res) => {
  const details = await provider.interactionDetails(req);
  // ...
});

// with koa
router.get('/interaction/:grant', async (ctx, next) => {
  const details = await provider.interactionDetails(ctx.req);
  // ...
});
```

**Provider#interactionFinished**
```js
// with express
expressApp.post('/interaction/:grant/login', async (req, res) => {
  await provider.interactionFinished(req, res, results); // result object below
  // ...
});

// with koa
router.post('/interaction/:grant', async (ctx, next) => {
  await provider.interactionFinished(ctx.req, ctx.res, results); // result object below
  // ...
});

// results should be an object with some or all the following properties
{
  // authentication/login prompt got resolved, omit if no authentication happened, i.e. the user
  // cancelled
  login: {
    account: '7ff1d19a-d3fd-4863-978e-8cce75fa880c', // logged-in account id
    acr: string, // acr value for the authentication
    remember: boolean, // true if provider should use a persistent cookie rather than a session one
    ts: number, // unix timestamp of the authentication
  },

  // consent was given by the user to the client for this session
  consent: {
    // use the scope property if you wish to remove/add scopes from the request, otherwise don't
    // include it use when i.e. offline_access was not given, or user declined to provide address
    scope: 'space separated list of scopes',
  },
  ['custom prompt name resolved']: {},
}
```


## Enable/Disable optional oidc-provider features

There are many features defined in OIDC which are optional and can be omitted to keep your
deployment compact. The feature flags with their default values are

| feature flag | enabled by default? |
| --- | --- |
| alwaysIssueRefresh | no |
| backchannelLogout | no |
| claimsParameter | no |
| clientCredentials | no |
| devInteractions | yes (!!!) |
| discovery | yes |
| encryption | no |
| introspection | no |
| mixupMitigation | no |
| oauthNativeApps | yes (forces pkce on with forcedForNative) |
| pkce | yes |
| registration | no |
| registrationManagement | no |
| request | no |
| requestUri | yes |
| revocation | no |
| sessionManagement | no |

**Development quick-start interactions**  
Development-ONLY out of the box interaction views bundled with the library allow you to skip the
boring frontend part while experimenting with oidc-provider. Enter any username (will be used as sub
claim value) and any password to proceed.

Be sure to disable and replace this feature with your actual frontend flows and End-User
authentication flows as soon as possible. These views are not meant to ever be seen by actual users.

```js
const configuration = { features: { devInteractions: Boolean[true] } };
```


**Discovery**  
Exposes `/.well-known/webfinger` and `/.well-known/openid-configuration` endpoints. Contents of the
latter reflect your actual configuration, i.e. available claims, features and so on.
```js
const configuration = { features: { discovery: Boolean[true] } };
```
WebFinger always returns positive results and links to this issuer, it is not resolving the resources
in any way.

**Authorization `claims` parameter**  
Enables the use and validations of `claims` parameter as described in [Core 1.0][core-claims-url]
and sets the discovery endpoint property `claims_parameter_supported` to true.
```js
const configuration = { features: { claimsParameter: Boolean[false] } };
```

**Token endpoint `client_credentials` grant**  
Enables `grant_type=client_credentials` to be used on the token endpoint. Note: client still has to
be allowed this grant.  
Hint: allowing this grant together with token introspection and revocation is an easy and elegant
way to allow authorized access to some less sensitive backend actions.
```js
const configuration = { features: { clientCredentials: Boolean[false] } };
```

**Encryption features**  
Enables clients to receive encrypted userinfo responses, encrypted ID Tokens and to send encrypted
request parameters to authorization.
```js
const configuration = { features: { encryption: Boolean[false] } };
```


**Offline access - Refresh Tokens**  
The use of Refresh Tokens (offline access) as described in [Core 1.0 Offline Access][core-offline-access]
does not require any feature flag as Refresh Tokens will be issued by the authorization_code grant
automatically in case the authentication request included offline_access scope and consent prompt and
the client in question has the refresh_token grant configured.

**Refresh Tokens beyond the spec scope**  
  > The use of Refresh Tokens is not exclusive to the offline_access use case. The Authorization
  > Server MAY grant Refresh Tokens in other contexts that are beyond the scope of this specification.

Provide `alwaysIssueRefresh` feature flag to have your provider instance issue Refresh Tokens even
if offline_access scope is not requested. The client still has to have refresh_token grant
configured, else no Refresh Token will be issued since the client couldn't finish the grant anyway.

```js
const configuration = { features: { alwaysIssueRefresh: Boolean[false] } };
```


**Authorization `request` parameter**  
Enables the use and validations of `request` parameter as described in
[Core 1.0][core-jwt-parameters-url] and sets the discovery endpoint property
`request_parameter_supported` to true.

```js
const configuration = { features: { request: Boolean[false] } };
```


**Authorization `request_uri` parameter**  
Enables the use and validations of `request_uri` parameter as described in
[Core 1.0][core-jwt-parameters-url] and sets the discovery endpoint property
`request_uri_parameter_supported` and `require_request_uri_registration` to true.
```js
const configuration = { features: { requestUri: Boolean[true] } };
```

To disable require_request_uri_registration configure requestUri as an object like so:
```js
const configuration = { features: { requestUri: { requireRequestUriRegistration: false } } };
```

**Introspection endpoint**  
Enables the use of Introspection endpoint as described in [RFC7662][introspection] for
tokens of type AccessToken, ClientCredentials and RefreshToken. When enabled the
introspection_endpoint property of the discovery endpoint is published, otherwise the property
is not sent. The use of this endpoint is covered by the same authz mechanism as the regular token
endpoint.
```js
const configuration = { features: { introspection: Boolean[false] } };
```

This feature is a recommended way for Resource Servers to validate presented Bearer tokens, since
the token endpoint access must be authorized it is recommended to setup a client for the RS to
use. This client should be unusable for standard authorization flow, to set up such a client provide
grant_types, response_types and redirect_uris as empty arrays.


**Revocation endpoint**  
Enables the use of Revocation endpoint as described in [RFC7009][revocation] for tokens of
type AccessToken, ClientCredentials and RefreshToken. When enabled the
revocation_endpoint property of the discovery endpoint is published, otherwise the property
is not sent. The use of this endpoint is covered by the same authz mechanism as the regular token
endpoint.
```js
const configuration = { features: { revocation: Boolean[false] } };
```


**OAuth 2.0 Native Apps Best Current Practice**
Changes `redirect_uris` validations for clients with application_type `native` to those defined in
[OAuth 2.0 for Native Apps][oauth-native-apps]. If pkce is not enabled it will be enabled
automatically so that AppAuth SDKs work out of the box. (🤞)
```js
const configuration = { features: { oauthNativeApps: Boolean[true] } };
```

**OAuth 2.0 Mix-Up Mitigation**
Enables additional authorization response parameters and token endpoint validations defined in
[OAuth 2.0 Mix-Up Mitigation - draft 01][mixup-mitigation].
```js
const configuration = { features: { mixupMitigation: Boolean[false] } };
```


**Session management features**  
Enables features described in [Session Management 1.0 - draft 28][session-management].
```js
const configuration = { features: { sessionManagement: Boolean[false] } };
```

To disable removing frame-ancestors from Content-Security-Policy and X-Frame-Options in
`check_session_iframe` calls because you know what you're doing with them, set:
```js
const configuration = { features: { sessionManagement: { keepHeaders: true } } };
```


**Back-Channel Logout features**  
Enables features described in [Back-Channel Logout 1.0 - draft 04][backchannel-logout].
```js
const configuration = { features: { sessionManagement: true, backchannelLogout: Boolean[false] } };
```


**Dynamic registration features**  
Enables features described in [Dynamic Client Registration 1.0][registration].
```js
const configuration = { features: { registration: Boolean[false] } };
```

To provide your own factory to get a new clientId:
```js
const configuration = { features: { registration: { idFactory: () => randomValue() } } };
```

To enable a fixed Initial Access Token for the registration POST call configure registration to be
an object like so:
```js
const configuration = { features: { registration: { initialAccessToken: 'tokenValue' } } };
```

To enable a Initial Access Token lookup from your storage (via an Adapter of course) configure
registration to be an object like so:
```js
const configuration = { features: { registration: { initialAccessToken: true } } };

// adding a token and retrieving it's value
new (provider.InitialAccessToken)({}).save().then(console.log);
```

**Dynamic registration management features**  
Enables Update and Delete features described in
[OAuth 2.0 Dynamic Client Registration Management Protocol][registration-management].
```js
const configuration = { features: { registration: true, registrationManagement: Boolean[false] } };
```

To have your provider discard the used and issue new RegistrationAccessToken with a successful update
configure registrationManagement as an object like so:
```js
const configuration = { features: { ..., registrationManagement: { rotateRegistrationAccessToken: true } } };
```

**PKCE**  
Enables [RFC7636 - Proof Key for Code Exchange by OAuth Public Clients][pkce]
```js
const configuration = { features: { pkce: Boolean[true] } };
```

To have native clients using code or hybrid flow forced to use pkce configure pkce as an object
like so:
```js
const configuration = { features: { pkce: { forcedForNative: true } } };
```


## Custom Grant Types
oidc-provider comes with the basic grants implemented, but you can register your own grant types,
for example to implement a [password grant type][password-grant]. You can check the standard
grant factories [here](/lib/actions/token).

```js
const parameters = ['username', 'password'];

provider.registerGrantType('password', function passwordGrantTypeFactory(providerInstance) {
  return async function passwordGrantType(ctx, next) {
    if (ctx.oidc.params.username === 'foo' && ctx.oidc.params.password === 'bar') {
      const AccessToken = providerInstance.AccessToken;
      const at = new AccessToken({
        accountId: 'foo',
        clientId: ctx.oidc.client.clientId,
        grantId: ctx.oidc.uuid,
      });

      const accessToken = await at.save();
      const expiresIn = AccessToken.expiresIn;

      ctx.body = {
        access_token: accessToken,
        expires_in: expiresIn,
        token_type: 'Bearer',
      };
    } else {
      ctx.body = {
        error: 'invalid_grant',
        error_description: 'invalid credentials provided',
      };
      ctx.status = 400;
    }

    await next();
  };
}, parameters);
```


## Extending Authorization with Custom Parameters
You can extend the whitelisted parameters of authorization/authentication endpoint beyond the
defaults. These will be available in ctx.oidc.params as well as passed via the `_grant` cookie
to the interaction.
```js
const oidc = new Provider('http://localhost:3000', {
  extraParams: ['utm_campaign', 'utm_medium', 'utm_source', 'utm_term'],
});
```


## Extending Discovery with Custom Properties
You can extend the returned discovery properties beyond the defaults
```js
const oidc = new Provider('http://localhost:3000', {
  discovery: {
    service_documentation: 'http://server.example.com/connect/service_documentation.html',
    ui_locales_supported: ['en-US', 'en-GB', 'en-CA', 'fr-FR', 'fr-CA'],
    version: '3.1'
  }
});
```


## Configuring Routes
You can change the default routes by providing a routes object to the oidc-provider constructor.
See the specific routes in [default configuration][defaults].

```js
const oidc = new Provider('http://localhost:3000', {
  routes: {
    authorization: '/authz',
    certificates: '/jwks'
  }
});
```


## Fine-tuning supported algorithms
The lists of supported algorithms exposed via discovery and used when validating request objects and
client metadata is a union of

- all symmetrical algorithsm where they apply
- algorithms from the keystore you initialize the provider with

If you wish to tune the algorithms further you may do so via the `unsupported` [configuration][defaults]
property.


## Changing HTTP Request Defaults
On four occasions the OIDC Provider needs to venture out to he world wide webs to fetch or post
to external resources, those are

- fetching an authorization request by request_uri reference
- fetching and refreshing client's referenced asymmetric keys (jwks_uri client metadata)
- validating pairwise client's relation to a sector (sector_identifier_uri client metadata)
- posting to client's backchannel_logout_uri

oidc-provider uses [got][got-library] for http requests with the following default request options
```js
const DEFAULT_HTTP_OPTIONS = {
  followRedirect: false,
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${this.issuer}; ${pkg.homepage})` },
  retries: 0,
  timeout: 1500,
};
```

Setting `defaultHttpOptions` on `Provider` instance merges your passed options with these defaults,
for example you can add your own headers, change the user-agent used or change the timeout setting
```js
provider.defaultHttpOptions = { timeout: 2500, headers: { 'X-Your-Header': '<whatever>' } };
```

Confirm your httpOptions by
```js
console.log('httpOptions %j', provider.defaultHttpOptions);
```

## Authentication Context Class Reference
Supply an array of string values to acrValues configuration option to set `acr_values_supported`.
Passing an empty array disables the acr claim and removes `acr_values_supported` from discovery.


## Mounting oidc-provider
The following snippets show how a provider instance can be mounted to existing applications with a
path prefix. As shown it is recommended to rewrite the well-known uri calls so that they get handled
by the provider.

### to an express application
```js
const rewrite = require('express-urlrewrite');
const prefix = '/oidc';
expressApp.use(rewrite('/.well-known/*', `${prefix}/.well-known/$1`));
expressApp.use(prefix, oidc.callback);
```

### to a koa application
```js
const rewrite = require('koa-rewrite');
const mount = require('koa-mount');
const prefix = '/oidc';
koaApp.use(rewrite('/.well-known/*', `${prefix}/.well-known/$1`));
koaApp.use(mount(prefix, oidc.app));
```

## Trusting ssl offloading proxies
Having a TLS offloading proxy in front of node.js running oidc-provider is the norm. As with
any express/koa application you have to tell your app to trust `x-forwarded-proto` and `x-forwarded-for`
headers commonly set by those proxies to let the downstream application know of the original protocol
and ip.

Depending on your setup you should do the following

| setup | example |
|---|---|
| standalone oidc-provider | `provider.app.proxy = true; ` |
| oidc-provider mounted to a koa app | `yourKoaApp.proxy = true` |
| oidc-provider mounted to an express app | `provider.app.proxy = true; ` |

[client-metadata]: http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
[core-account-claims]: http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
[core-offline-access]: http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
[core-claims-url]: http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
[core-jwt-parameters-url]: http://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
[aggregated-distributed-claims]: http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
[backchannel-logout]: http://openid.net/specs/openid-connect-backchannel-1_0-04.html
[pkce]: https://tools.ietf.org/html/rfc7636
[introspection]: https://tools.ietf.org/html/rfc7662
[registration-management]: https://tools.ietf.org/html/rfc7592
[registration]: http://openid.net/specs/openid-connect-registration-1_0.html
[revocation]: https://tools.ietf.org/html/rfc7009
[oauth-native-apps]: https://tools.ietf.org/html/draft-ietf-oauth-native-apps-07
[session-management]: http://openid.net/specs/openid-connect-session-1_0-28.html
[got-library]: https://github.com/sindresorhus/got
[password-grant]: https://tools.ietf.org/html/rfc6749#section-4.3
[defaults]: /lib/helpers/defaults.js
[mixup-mitigation]: https://tools.ietf.org/html/draft-ietf-oauth-mix-up-mitigation-01
