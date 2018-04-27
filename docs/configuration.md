# Configuration

oidc-provider allows to be extended and configured in various ways to fit a variety of uses. You
SHOULD tell your instance how to find your user accounts, where to store and retrieve persisted data
from and where your user-interaction happens. The [example](/example) application is a good starting
point to get an idea of what you should provide.

**Table of Contents**

<!-- TOC START min:2 max:3 link:true update:true -->
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
  - [HTTP Request Library / Proxy settings](#http-request-library--proxy-settings)
  - [Changing HTTP Request Defaults](#changing-http-request-defaults)
  - [Authentication Context Class Reference](#authentication-context-class-reference)
  - [Registering module middlewares (helmet, ip-filters, rate-limiters, etc)](#registering-module-middlewares-helmet-ip-filters-rate-limiters-etc)
  - [Pre- and post-middlewares](#pre--and-post-middlewares)
  - [Mounting oidc-provider](#mounting-oidc-provider)
    - [to an express application](#to-an-express-application)
    - [to a koa application](#to-a-koa-application)
  - [Trusting TLS offloading proxies](#trusting-tls-offloading-proxies)
  - [Configuration options](#configuration-options)
    - [acrValues](#acrvalues)
    - [audiences](#audiences)
    - [claims](#claims)
    - [clientCacheDuration](#clientcacheduration)
    - [clockTolerance](#clocktolerance)
    - [cookies](#cookies)
    - [cookies.keys](#cookieskeys)
    - [cookies.long](#cookieslong)
    - [cookies.names](#cookiesnames)
    - [cookies.short](#cookiesshort)
    - [discovery](#discovery)
    - [extraClientMetadata](#extraclientmetadata)
    - [extraClientMetadata.properties](#extraclientmetadataproperties)
    - [extraClientMetadata.validator](#extraclientmetadatavalidator)
    - [extraParams](#extraparams)
    - [features](#features)
    - [findById](#findbyid)
    - [frontchannelLogoutPendingSource](#frontchannellogoutpendingsource)
    - [interactionCheck](#interactioncheck)
    - [interactionUrl](#interactionurl)
    - [introspectionEndpointAuthMethods](#introspectionendpointauthmethods)
    - [logoutSource](#logoutsource)
    - [pairwiseSalt](#pairwisesalt)
    - [postLogoutRedirectUri](#postlogoutredirecturi)
    - [prompts](#prompts)
    - [refreshTokenRotation](#refreshtokenrotation)
    - [renderError](#rendererror)
    - [responseTypes](#responsetypes)
    - [revocationEndpointAuthMethods](#revocationendpointauthmethods)
    - [routes](#routes)
    - [scopes](#scopes)
    - [subjectTypes](#subjecttypes)
    - [tokenEndpointAuthMethods](#tokenendpointauthmethods)
    - [ttl](#ttl)
    - [uniqueness](#uniqueness)
    - [unsupported](#unsupported)

<!-- TOC END -->

## Default configuration values
Default values are available for all configuration options. Available in [code][defaults] as well as
in this [document](#configuration-options).


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
      async claims(use, scope) { return { sub: id }; },
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

Available [Client Metadata][client-metadata] is validated as defined by the specifications. This list
is extended by other adjacent-specification related properties such as introspection and revocation
endpoint authentication, Session Management, Front and Back-Channel Logout, etc.

Note: each oidc-provider caches the clients once they are loaded. When your adapter-stored client
configuration changes you should either reload your processes or trigger a cache clear
(`provider.Client.cacheClear()` or `provider.Client.cacheClear(id)`).

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
storing issued tokens, codes, user sessions and dynamically registered clients. This is fine as
long as you develop, configure and generally just play around since every time you restart your
process all information will be lost. As soon as you cannot live with this limitation you will be
required to provide your own custom adapter constructor for oidc-provider to
use. This constructor will be called for every model accessed the first time it
is needed. A static `connect` method is called if present during the initialize phase.

```js
const MyAdapter = require('./my_adapter');
const oidc = new Provider('http://localhost:3000');
oidc.initialize({
  adapter: MyAdapter
});
```

The API oidc-provider expects is documented [here](/example/my_adapter.js). For reference see the
[memory adapter](/lib/adapters/memory_adapter.js) and [redis](/example/adapters/redis.js) or
[mongodb](/example/adapters/mongodb.js) adapters. There's also a simple
[adapter conformance test](/lib/adapter_test.js) that can be used to check your
own adapter implementation, (with already written tests for the
[redis](/example/adapters/redis_test.js) and the
[mongodb](/example/adapters/mongodb_test.js) implementations).


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
- current session account ID should there be one
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


**`#provider.interactionDetails(req)`**
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

**`#provider.interactionFinished(req, res, results)`**
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

  // meta is a free object you may store alongside an authorization. It can be useful
  // during the interactionCheck to verify information on the ongoing session.
  meta: {
    // object structure up-to-you
  },

  ['custom prompt name resolved']: {},
}

// optionally, interactions can be primaturely exited with a an error by providing a result
// object as follow:
{
  // an error field used as error code indicating a failure during the interaction
  error: 'access_denied',

  // an optional description for this error
  error_description: 'Insufficient permissions: scope out of reach for this Account',
}
```

**`#provider.setProviderSession`**
Sometimes interactions need to be interrupted before finishing and need to be picked up later,
or a session just needs to be established from outside the regular authorization request.
`#provider.setProviderSession` will take care of setting the proper cookies and storing the
updated/created session object.

Signature:
```js
async setProviderSession(req, res, {
  account, // account id string
  ts = epochTime(), // [optional] login timestamp, defaults to current timestamp
  remember = true, // [optional] set the session as persistent, defaults to true
  clients = [], // [optional] array of client id strings to pre-authorize in the updated session
} = {})
```

```js
// with express
expressApp.post('/interaction/:grant/login', async (req, res) => {
  await provider.setProviderSession(req, res, { account: 'accountId' });
  // ...
});

// with koa
router.post('/interaction/:grant/login', async (ctx, next) => {
  await provider.setProviderSession(ctx.req, ctx.res, { account: 'accountId' });
  // ...
});
```


## Enable/Disable optional oidc-provider features

There are many features defined in OIDC which are optional and can be omitted to keep your
deployment compact. The feature flags with their default values are

| feature flag | enabled by default? |
| --- | --- |
| devInteractions | yes (!!!) |
| backchannelLogout | no |
| frontchannelLogout | no |
| claimsParameter | no |
| clientCredentials | no |
| discovery | yes |
| encryption | no |
| introspection | no |
| alwaysIssueRefresh | no |
| registration | no |
| registrationManagement | no |
| request | no |
| requestUri | yes |
| revocation | no |
| oauthNativeApps | yes (forces pkce on with forcedForNative) |
| sessionManagement | no |
| pkce | yes |

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
endpoint or `introspection_endpoint_auth_method` and `introspection_endpoint_auth_signing_alg` if
defined on a client.
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
endpoint or `revocation_endpoint_auth_method` and `revocation_endpoint_auth_signing_alg` if
defined on a client.
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


**Front-Channel Logout features**  
Enables features described in [Front-Channel Logout 1.0 - draft 02][frontchannel-logout].
```js
const configuration = { features: { sessionManagement: true, frontchannelLogout: Boolean[false] } };
```


**Dynamic registration features**  
Enables features described in [Dynamic Client Registration 1.0][registration].
```js
const configuration = { features: { registration: Boolean[false] } };
```

To provide your own factory to get a new client_id:
```js
const configuration = { features: { registration: { idFactory: () => randomValue() } } };
```

To provide your own factory to get a random client_secret:
```js
const configuration = { features: { registration: { secretFactory: () => randomValue() } } };
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

To fine-tune the supported methods:
```js
const configuration = { features: { pkce: { supportedMethods: ['plain', 'S256'] } } };
```


## Custom Grant Types
oidc-provider comes with the basic grants implemented, but you can register your own grant types,
for example to implement a [password grant type][password-grant]. You can check the standard
grant factories [here](/lib/actions/grants).

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
defaults. These will be available in ctx.oidc.params as well as passed to the interaction session
object for you to read.
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

- all symmetrical algorithms where they apply
- algorithms from the keystore you initialize the provider with

If you wish to tune the algorithms further you may do so via the `unsupported` [configuration][defaults]
property.

## HTTP Request Library / Proxy settings
By default oidc-provider uses the [got][got-library] module. Because of its lightweight nature of
the provider will not use environment-defined http(s) proxies. In order to have them used you'll
need to require and tell oidc-provider to use [request][request-library] instead.

```sh
# add request to your application package bundle
npm install request@^2.0.0 --save
```

```js
// tell oidc-provider to use request instead of got
Provider.useRequest();
```


## Changing HTTP Request Defaults
On four occasions the OIDC Provider needs to venture out to the world wide webs to fetch or post
to external resources, those are

- fetching an authorization request by request_uri reference
- fetching and refreshing client's referenced asymmetric keys (jwks_uri client metadata)
- validating pairwise client's relation to a sector (sector_identifier_uri client metadata)
- posting to client's backchannel_logout_uri

oidc-provider uses these default options for http requests
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


## Registering module middlewares (helmet, ip-filters, rate-limiters, etc)
When using `provider.app` or `provider.callback` as a mounted application in your own koa or express
stack just follow the respective module's documentation. However, when using the `provider.app` Koa
instance directly to register i.e. koa-helmet you must push the middleware in
front of oidc-provider in the middleware stack.

```js
const helmet = require('koa-helmet');

// Correct, pushes koa-helmet at the end of the middleware stack but BEFORE oidc-provider.
provider.use(helmet());

// Incorrect, pushes koa-helmet at the end of the middleware stack AFTER oidc-provider, not being
// executed when errors are encountered or during actions that do not "await next()".
provider.app.use(helmet());
```


## Pre- and post-middlewares
You can push custom middleware to be executed before and after oidc-provider.

```js
provider.use(async (ctx, next) => {
  // pre-processing
  // you may target a specific action here by matching `ctx.path`
  console.log('middleware pre', ctx.method, ctx.path);
  await next();
  console.log('middleware post', ctx.method, ctx._matchedRouteName);
  // post-processing
  // since internal route matching was already executed you may target a specific action here
  // checking `ctx._matchedRouteName`, the unique route names used are "authorization", "token",  
  // "discovery", "registration", "userinfo", "resume", "certificates", "webfinger",
  // "client", "client_update", "client_delete", "introspection", "revocation",
  // "check_session" and "end_session". ctx.method === 'OPTIONS' is then useful for filtering out
  // CORS Pre-flights
});
```

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
koaApp.use(rewrite('/.well-known/(.*)', `${prefix}/.well-known/$1`));
koaApp.use(mount(prefix, oidc.app));
```

## Trusting TLS offloading proxies

Having a TLS offloading proxy in front of Node.js running oidc-provider is
the norm. To let your downstream application know of the original protocol and
ip you have to tell your app to trust `x-forwarded-proto` and `x-forwarded-for`
headers commonly set by those proxies (as with any express/koa application).
This is needed for the provider responses to be correct (e.g. to have the right
https URL endpoints and keeping the right (secure) protocol).

Depending on your setup you should do the following in your downstream
application code

| setup | example |
|---|---|
| standalone oidc-provider | `provider.proxy = true; ` |
| oidc-provider mounted to a koa app | `yourKoaApp.proxy = true` |
| oidc-provider mounted to an express app | `provider.proxy = true; ` |

See http://koajs.com/#settings and the [example](/example/index.js).

It is also necessary that the web server doing the offloading also passes
those headers to the downstream application. Here is a common configuration
for Nginx (assuming that the downstream application is listening on
127.0.0.1:8009). Your configuration may vary, please consult your web server
documentation for details.

```
location / {
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;

  proxy_pass http://127.0.0.1:8009;
  proxy_redirect off;
}
```

## Configuration options

<!-- START CONF OPTIONS -->
### acrValues

Array of strings, the Authentication Context Class References that OP supports. First one in the list will be the one used for authentication requests unless one was provided as part of an interaction result. Use a value with 'session' meaning as the first.  

affects: discovery, ID Token acr claim values  

default value:
```js
[]
```

### audiences

Helper used by the OP to push additional audiences to issued ID Tokens and other signed responses. The return value should either be falsy to omit adding additional audiences or an array of strings to push.  

affects: id token audiences, signed userinfo audiences  

default value:
```js
async audiences(ctx, sub, token, use, scope) {
  // @param ctx   - koa request context
  // @param sub   - account identifier (subject)
  // @param token - a reference to the token used for which a given account is being loaded,
  //   is undefined in scenarios where claims are returned from authorization endpoint
  // @param use   - can be one of "id_token", "userinfo", "access_token" depending on where the
  //   specific audiences are intended to be put in
  // @param scope - scope from either the request or related token
  return undefined;
}
```

### claims

List of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.  

affects: discovery, ID Token claim names, Userinfo claim names  

default value:
```js
{ acr: null, auth_time: null, iss: null, openid: [ 'sub' ] }
```

### clientCacheDuration

A `Number` value (in seconds) describing how long a dynamically loaded client should remain cached.  

affects: adapter-backed client cache duration  

default value:
```js
Infinity
```

### clockTolerance

A `Number` value (in seconds) describing the allowed system clock skew  

affects: JWT (ID token, client assertion) validations.  
recommendation: Set to a reasonable value (60) to cover server-side client and oidc-provider server clock skew  

default value:
```js
0
```

### cookies

Options for the [cookie module][module-cookies] used by the OP to keep track of various User-Agent states.  

affects: User-Agent sessions, passing of authorization details to interaction  

### cookies.keys

[Keygrip][keygrip-module] Signing keys used for cookie signing to prevent tampering.  

recommendation: Rotate regularly (by prepending new keys) with a reasonable interval and keep a reasonable history of keys to allow for returning user session cookies to still be valid and re-signed  

default value:
```js
[]
```

### cookies.long

Options for long-term cookies  

affects: User-Agent session reference, Session Management states  
recommendation: set cookies.keys and cookies.long.signed = true  

default value:
```js
{ secure: undefined,
  signed: undefined,
  httpOnly: true,
  maxAge: 31557600000 }
```

### cookies.names

Cookie names used by the OP to store and transfer various states.  

affects: User-Agent session, Session Management states and interaction cookie names  

default value:
```js
{ session: '_session',
  interaction: '_grant',
  resume: '_grant',
  state: '_state' }
```

### cookies.short

Options for short-term cookies  

affects: passing of authorization details to interaction  
recommendation: set cookies.keys and cookies.short.signed = true  

default value:
```js
{ secure: undefined,
  signed: undefined,
  httpOnly: true,
  maxAge: 3600000 }
```

### discovery

Pass additional properties to this object to extend the discovery document  

affects: discovery  

default value:
```js
{ claim_types_supported: [ 'normal' ],
  claims_locales_supported: undefined,
  display_values_supported: undefined,
  op_policy_uri: undefined,
  op_tos_uri: undefined,
  service_documentation: undefined,
  ui_locales_supported: undefined }
```

### extraClientMetadata

Allows for custom client metadata to be defined, validated, manipulated as well as for existing property validations to be extended  

affects: clients, registration, registration management  

### extraClientMetadata.properties

Array of property names that clients will be allowed to have defined. Property names will have to strictly follow the ones defined here. However, on a Client instance property names will be snakeCased.  


default value:
```js
[]
```

### extraClientMetadata.validator

validator function that will be executed in order once for every property defined in `extraClientMetadata.properties`, regardless of its value or presence on the client metadata passed in. Must be synchronous, async validators or functions returning Promise will be rejected during runtime. To modify the current client metadata values (for current key or any other) just modify the passed in `metadata` argument.  


default value:
```js
validator(key, value, metadata) {
  // validations for key, value, other related metadata
  // throw new Provider.InvalidClientMetadata() to reject the client metadata (see all errors on
  //   Provider)
  // metadata[key] = value; to assign values
  // return not necessary, metadata is already a reference.
}
```

### extraParams

Pass an iterable object (i.e. Array or set of strings) to extend the parameters recognized by the authorization endpoint. These parameters are then available in ctx.oidc.params as well as passed to interaction session details  

affects: authorization, interaction  

default value:
```js
[]
```

### features

Enable/disable features, see configuration.md for more details  


default value:
```js
{ devInteractions: true,
  discovery: true,
  requestUri: true,
  oauthNativeApps: true,
  pkce: true,
  backchannelLogout: false,
  frontchannelLogout: false,
  claimsParameter: false,
  clientCredentials: false,
  encryption: false,
  introspection: false,
  alwaysIssueRefresh: false,
  registration: false,
  registrationManagement: false,
  request: false,
  revocation: false,
  sessionManagement: false }
```

### findById

Helper used by the OP to load your account and retrieve it's available claims. The return value should be a Promise and #claims() can return a Promise too  

affects: authorization, authorization_code and refresh_token grants, id token claims  

default value:
```js
async findById(ctx, sub, token) {
  // @param ctx   - koa request context
  // @param sub   - account identifier (subject)
  // @param token - is a reference to the token used for which a given account is being loaded,
  //   is undefined in scenarios where claims are returned from authorization endpoint
  return {
    accountId: sub,
    // @param use   - can either be "id_token" or "userinfo", depending on
    //   where the specific claims are intended to be put in
    // @param scope - the intended scope, while oidc-provider will mask
    //   claims depending on the scope automatically you might want to skip
    //   loading some claims from external resources etc. based on this detail
    //   or not return them in id tokens but only userinfo and so on
    async claims(use, scope) {
      return { sub };
    },
  };
}
```

### frontchannelLogoutPendingSource

HTML source rendered when there are pending front-channel logout iframes to be called to trigger RP logouts. It should handle waiting for the frames to be loaded as well as have a timeout mechanism in it.  

affects: session management  

default value:
```js
async frontchannelLogoutPendingSource(ctx, frames, postLogoutRedirectUri, timeout) {
  ctx.body = `<!DOCTYPE html>
<head>
<title>Logout</title>
<style>
  iframe {
    visibility: hidden;
    position: absolute;
    left: 0;
    top: 0;
    height:0;
    width:0;
    border: none;
  }
</style>
</head>
<body>
${frames.join('')}
<script>
  var loaded = 0;
  function redirect() {
    window.location.replace("${postLogoutRedirectUri}");
  }
  function frameOnLoad() {
    loaded += 1;
    if (loaded === ${frames.length}) redirect();
  }
  Array.prototype.slice.call(document.querySelectorAll('iframe')).forEach(function (element) {
    element.onload = frameOnLoad;
  });
  setTimeout(redirect, ${timeout});
</script>
</body>
</html>`;
}
```

### interactionCheck

Helper used by the OP as a final check whether the End-User should be sent to interaction or not, the default behavior is that every RP must be authorized per session and that native application clients always require End-User prompt to be confirmed. Return false if no interaction should be performed, return an object with relevant error, reason, etc. When interaction should be requested  

affects: authorization interactions  

default value:
```js
async interactionCheck(ctx) {
  if (!ctx.oidc.session.sidFor(ctx.oidc.client.clientId)) {
    return {
      error: 'consent_required',
      error_description: 'client not authorized for End-User session yet',
      reason: 'client_not_authorized',
    };
  } else if (
    ctx.oidc.client.applicationType === 'native' &&
    ctx.oidc.params.response_type !== 'none' &&
    !ctx.oidc.result) {
    return {
      error: 'interaction_required',
      error_description: 'native clients require End-User interaction',
      reason: 'native_client_prompt',
    };
  }
  return false;
}
```

### interactionUrl

Helper used by the OP to determine where to redirect User-Agent for necessary interaction, can return both absolute and relative urls  

affects: authorization interactions  

default value:
```js
async interactionUrl(ctx, interaction) {
  return `/interaction/${ctx.oidc.uuid}`;
}
```

### introspectionEndpointAuthMethods

List of Client Authentication methods supported by this OP's Introspection Endpoint  

affects: discovery, client authentication for introspection, registration and registration management  

default value:
```js
[ 'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt' ]
```

### logoutSource

HTML source to which a logout form source is passed when session management renders a confirmation prompt for the User-Agent.  

affects: session management  

default value:
```js
async logoutSource(ctx, form) {
  ctx.body = `<!DOCTYPE html>
<head>
<title>Logout</title>
</head>
<body>
<script>
  function logout() {
    var form = document.getElementById('op.logoutForm');
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'logout';
    input.value = 'yes';
    form.appendChild(input);
    form.submit();
  }
</script>
${form}
Do you want to logout from OP too?
<button onclick="logout()">Yes</button>
<button onclick="document.getElementById('op.logoutForm').submit()">Please, don't!</button>
</body>
</html>`;
}
```

### pairwiseSalt

Salt used by OP when resolving pairwise ID Token and Userinfo sub claim value  

affects: ID Token and Userinfo sub claim values  

default value:
```js
''
```

### postLogoutRedirectUri

URL to which the OP redirects the User-Agent when no post_logout_redirect_uri is provided by the RP  

affects: session management  

default value:
```js
async postLogoutRedirectUri(ctx) {
  return ctx.origin;
}
```

### prompts

List of the prompt values that the OpenID Provider MAY be able to resolve  

affects: authorization  

default value:
```js
[ 'consent', 'login', 'none' ]
```

### refreshTokenRotation

Configures if and how the OP rotates refresh tokens after they are used. Supported values are 1) `"none"` when refresh tokens are not rotated and their initial expiration date is final or 2) `"rotateAndConsume"` when refresh tokens are rotated when used, current token is marked as consumed and new one is issued with new TTL, when a consumed refresh token is encountered an error is returned instead and the whole token chain (grant) is revoked.  

affects: refresh token rotation and adjacent revocation  

default value:
```js
'rotateAndConsume'
```

### renderError

Helper used by the OP to present errors which are not meant to be 'forwarded' to the RP's redirect_uri  

affects: presentation of errors encountered during authorization  

default value:
```js
async renderError(ctx, error) {
  ctx.type = 'html';
  ctx.body = `<!DOCTYPE html>
<head>
<title>oops! something went wrong</title>
</head>
<body>
<h1>oops! something went wrong</h1>
<pre>${JSON.stringify(error, null, 4)}</pre>
</body>
</html>`;
}
```

### responseTypes

List of response_type values that OP supports  

affects: authorization, discovery, registration, registration management  

default value:
```js
[ 'code id_token token',
  'code id_token',
  'code token',
  'code',
  'id_token token',
  'id_token',
  'none' ]
```

### revocationEndpointAuthMethods

List of Client Authentication methods supported by this OP's Revocation Endpoint  

affects: discovery, client authentication for revocation, registration and registration management  

default value:
```js
[ 'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt' ]
```

### routes

Routing values used by the OP. Only provide routes starting with "/"  

affects: routing  

default value:
```js
{ authorization: '/auth',
  certificates: '/certs',
  check_session: '/session/check',
  end_session: '/session/end',
  introspection: '/token/introspection',
  registration: '/reg',
  revocation: '/token/revocation',
  token: '/token',
  userinfo: '/me' }
```

### scopes

List of the scope values that the OP supports  

affects: discovery, authorization, ID Token claims, Userinfo claims  

default value:
```js
[ 'openid', 'offline_access' ]
```

### subjectTypes

List of the Subject Identifier types that this OP supports. Valid types include 'pairwise' and 'public'.  

affects: discovery, registration, registration management, ID Token and Userinfo sub claim values  

default value:
```js
[ 'public' ]
```

### tokenEndpointAuthMethods

List of Client Authentication methods supported by this OP's Token Endpoint  

affects: discovery, client authentication for token endpoint, registration and registration management  

default value:
```js
[ 'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt' ]
```

### ttl

Expirations (in seconds) for all token types  

affects: tokens  

default value:
```js
{ AccessToken: 3600,
  AuthorizationCode: 600,
  ClientCredentials: 600,
  IdToken: 3600,
  RefreshToken: 1209600 }
```

### uniqueness

Function resolving whether a given value with expiration is presented first time  

affects: client_secret_jwt and private_key_jwt client authentications  
recommendation: configure this option to use a shared store if client_secret_jwt and private_key_jwt are used  

default value:
```js
async uniqueness(ctx, jti, expiresAt) {
  if (cache.get(jti)) return false;
  cache.set(jti, true, (expiresAt - epochTime()) * 1000);
  return true;
}
```

### unsupported

Fine-tune the algorithms your provider should support by further omitting values from the respective discovery properties  

affects: signing, encryption, discovery, client validation  

default value:
```js
{ idTokenEncryptionAlgValues: [],
  idTokenEncryptionEncValues: [],
  idTokenSigningAlgValues: [],
  requestObjectEncryptionAlgValues: [],
  requestObjectEncryptionEncValues: [],
  requestObjectSigningAlgValues: [],
  tokenEndpointAuthSigningAlgValues: [],
  introspectionEndpointAuthSigningAlgValues: [],
  revocationEndpointAuthSigningAlgValues: [],
  userinfoEncryptionAlgValues: [],
  userinfoEncryptionEncValues: [],
  userinfoSigningAlgValues: [] }
```
<!-- END CONF OPTIONS -->

[client-metadata]: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
[core-account-claims]: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
[core-offline-access]: https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
[core-claims-url]: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
[core-jwt-parameters-url]: https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
[aggregated-distributed-claims]: https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
[backchannel-logout]: https://openid.net/specs/openid-connect-backchannel-1_0-04.html
[frontchannel-logout]: https://openid.net/specs/openid-connect-frontchannel-1_0-02.html
[pkce]: https://tools.ietf.org/html/rfc7636
[introspection]: https://tools.ietf.org/html/rfc7662
[registration-management]: https://tools.ietf.org/html/rfc7592
[registration]: https://openid.net/specs/openid-connect-registration-1_0.html
[revocation]: https://tools.ietf.org/html/rfc7009
[oauth-native-apps]: https://tools.ietf.org/html/rfc8252
[session-management]: https://openid.net/specs/openid-connect-session-1_0-28.html
[got-library]: https://github.com/sindresorhus/got
[request-library]: https://github.com/request/request
[password-grant]: https://tools.ietf.org/html/rfc6749#section-4.3
[defaults]: /lib/helpers/defaults.js
[cookie-module]: https://github.com/pillarjs/cookies#cookiesset-name--value---options--
[keygrip-module]: https://www.npmjs.com/package/keygrip
