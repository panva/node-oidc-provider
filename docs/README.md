# oidc-provider API documentation

oidc-provider allows to be extended and configured in various ways to fit a variety of use cases. You
will have to configure your instance with how to find your user accounts, where to store and retrieve
persisted data from and where your end-user interactions happen. The [example](/example) application
is a good starting point to get an idea of what you should provide.

> ⚠️⚠️ This page now describes oidc-provider version v7.x documentation. See 
[here](https://github.com/panva/node-oidc-provider/blob/v6.x/docs/README.md) for v6.x.

## Support

If you or your business use oidc-provider, or you need help using/upgrading the module, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree. The only way to guarantee you get feedback from the author & sole maintainer of this module is to support the package through GitHub Sponsors.

<br>

---

**Table of Contents**

- [Basic configuration example](#basic-configuration-example)
- [Accounts](#accounts)
- [User flows](#user-flows)
- [Custom Grant Types ❗](#custom-grant-types)
- [Registering module middlewares (helmet, ip-filters, rate-limiters, etc)](#registering-module-middlewares-helmet-ip-filters-rate-limiters-etc)
- [Pre- and post-middlewares ❗](#pre--and-post-middlewares)
- [Mounting oidc-provider](#mounting-oidc-provider)
  - [to a connect application](#to-a-connect-application)
  - [to a fastify application](#to-a-fastify-application)
  - [to a nest application](#to-a-nest-application)
  - [to a hapi application](#to-a-hapi-application)
  - [to a koa application](#to-a-koa-application)
  - [to an express application](#to-an-express-application)
- [Trusting TLS offloading proxies ❗](#trusting-tls-offloading-proxies)
- [Configuration options ❗](#configuration-options)
- [FAQ ❗](#faq)



## Basic configuration example

```js
const { Provider } = require('oidc-provider');
const configuration = {
  // ... see the available options in Configuration options section
  clients: [{
    client_id: 'foo',
    client_secret: 'bar',
    redirect_uris: ['http://lvh.me:8080/cb'],
    // + other client properties
  }],
  // ...
};

const oidc = new Provider('http://localhost:3000', configuration);

// express/nodejs style application callback (req, res, next) for use with express apps, see /examples/express.js
oidc.callback()

// koa application for use with koa apps, see /examples/koa.js
oidc.app

// or just expose a server standalone, see /examples/standalone.js
const server = oidc.listen(3000, () => {
  console.log('oidc-provider listening on port 3000, check http://localhost:3000/.well-known/openid-configuration');
});
```


## Accounts

oidc-provider needs to be able to find an account and once found the account needs to have an
`accountId` property as well as `claims()` function returning an object with claims that correspond
to the claims your issuer supports. Tell oidc-provider how to find your account by an ID.
`#claims()` can also return a Promise later resolved / rejected.

```js
const oidc = new Provider('http://localhost:3000', {
  async findAccount(ctx, id) {
    return {
      accountId: id,
      async claims(use, scope) { return { sub: id }; },
    };
  }
});
```


## User flows
Since oidc-provider only comes with feature-less views and interaction handlers it is up to you to fill
those in, here is how oidc-provider allows you to do so:

When oidc-provider cannot fulfill the authorization request for any of the possible reasons (missing
user session, requested ACR not fulfilled, prompt requested, ...) it will resolve the 
[`interactions.url`](#interactionsurl) helper function and redirect the User-Agent to that url. Before
doing so it will save a short-lived "interaction session" and dump its identifier into a cookie scoped to the
resolved interaction path.

This interaction session contains:

- details of the interaction that is required
- all authorization request parameters
- current end-user session account ID should there be one
- the url to redirect the user to once interaction is finished

oidc-provider expects that you resolve the prompt interaction and then redirect the User-Agent back
with the results.

Once the required interactions are finished you are expected to redirect back to the authorization
endpoint, affixed by the uid of the interaction session and the interaction results stored in the
interaction session object.

The Provider instance comes with helpers that aid with getting interaction details as well as
packing the results. See them used in the [in-repo](/example) examples.


**`#provider.interactionDetails(req, res)`**
```js
// with express
expressApp.get('/interaction/:uid', async (req, res) => {
  const details = await provider.interactionDetails(req, res);
  // ...
});

// with koa
router.get('/interaction/:uid', async (ctx, next) => {
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  // ...
});
```

**`#provider.interactionFinished(req, res, result)`**
```js
// with express
expressApp.post('/interaction/:uid/login', async (req, res) => {
  return provider.interactionFinished(req, res, result); // result object below
});

// with koa
router.post('/interaction/:uid', async (ctx, next) => {
  return provider.interactionFinished(ctx.req, ctx.res, result); // result object below
});

// result should be an object with some or all the following properties
{
  // authentication/login prompt got resolved, omit if no authentication happened, i.e. the user
  // cancelled
  login: {
    accountId: '7ff1d19a-d3fd-4863-978e-8cce75fa880c', // logged-in account id
    acr: string, // acr value for the authentication
    remember: boolean, // true if provider should use a persistent cookie rather than a session one, defaults to true
    ts: number, // unix timestamp of the authentication, defaults to now()
  },

  // consent was given by the user to the client for this session
  consent: {
    grantId: string, // the identifer of Grant object you saved during the interaction, resolved by Grant.prototype.save()
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

**`#provider.interactionResult`**
Unlike `#provider.interactionFinished` authorization request resume uri is returned instead of
immediate http redirect.

```js
// with express
expressApp.post('/interaction/:uid/login', async (req, res) => {
  const redirectTo = await provider.interactionResult(req, res, result);

  res.send({ redirectTo });
});

// with koa
router.post('/interaction/:uid', async (ctx, next) => {
  const redirectTo = await provider.interactionResult(ctx.req, ctx.res, result);

  ctx.body = { redirectTo };
});
```


## Custom Grant Types
oidc-provider comes with the basic grants implemented, but you can register your own grant types,
for example to implement an 
[OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html). You can check the standard
grant factories [here](/lib/actions/grants).

```js
const parameters = [
  'audience', 'resource', 'scope', 'requested_token_type',
  'subject_token', 'subject_token_type',
  'actor_token', 'actor_token_type'
];
const allowedDuplicateParameters = ['audience', 'resource'];
const grantType = 'urn:ietf:params:oauth:grant-type:token-exchange';

async function tokenExchangeHandler(ctx, next) {
  // ctx.oidc.params holds the parsed parameters
  // ctx.oidc.client has the authenticated client

  // your grant implementation
  // see /lib/actions/grants for references on how to instantiate and issue tokens
}

provider.registerGrantType(grantType, tokenExchangeHandler, parameters, allowedDuplicateParameters);
```


## Registering module middlewares (helmet, ip-filters, rate-limiters, etc)
When using `provider.app` or `provider.callback()` as a mounted application in your own koa or express
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
  /** pre-processing
   * you may target a specific action here by matching `ctx.path`
   */
  console.log('pre middleware', ctx.method, ctx.path);

  await next();
  /** post-processing
   * since internal route matching was already executed you may target a specific action here
   * checking `ctx.oidc.route`, the unique route names used are
   *
   * `authorization`
   * `backchannel_authentication`
   * `client_delete`
   * `client_update`
   * `client`
   * `code_verification`
   * `cors.device_authorization`
   * `cors.discovery`
   * `cors.introspection`
   * `cors.jwks`
   * `cors.pushed_authorization_request`
   * `cors.revocation`
   * `cors.token`
   * `cors.userinfo`
   * `device_authorization`
   * `device_resume`
   * `discovery`
   * `end_session_confirm`
   * `end_session_success`
   * `end_session`
   * `introspection`
   * `jwks`
   * `pushed_authorization_request`
   * `registration`
   * `resume`
   * `revocation`
   * `token`
   * `userinfo`
   */
   console.log('post middleware', ctx.method, ctx.oidc.route);
});
```

## Mounting oidc-provider
The following snippets show how a provider instance can be mounted to existing applications with a
path prefix `/oidc`.

Note: if you mount oidc-provider to a path it's likely you will have to also update the 
[`interactions.url`](#interactionsurl) configuration to reflect the new path.

### to a `connect` application
```js
// assumes connect ^3.0.0
connectApp.use('/oidc', oidc.callback());
```

### to a `fastify` application
```js
// assumes fastify ^4.0.0
const fastify = new Fastify();
await fastify.register(require('@fastify/middie'));
// or
// await app.register(require('@fastify/express'));
fastify.use('/oidc', oidc.callback());
```

### to a `hapi` application
```js
// assumes @hapi/hapi ^20.0.0
const callback = oidc.callback();
hapiApp.route({
  path: `/oidc/{any*}`,
  method: '*',
  config: { payload: { output: 'stream', parse: false } },
  async handler({ raw: { req, res } }, h) {
    req.originalUrl = req.url;
    req.url = req.url.replace('/oidc', '');

    await new Promise((resolve) => {
      res.on('finish', resolve);
      callback(req, res);
    });

    req.url = req.url.replace('/', '/oidc');
    delete req.originalUrl;

    return res.finished ? h.abandon : h.continue;
  }
});
```

### to a `nest` application
```ts
// assumes NestJS ^7.0.0
import { Controller, All, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
const callback = oidc.callback();
@Controller('oidc')
export class OidcController {
  @All('/*')
  public mountedOidc(@Req() req: Request, @Res() res: Response): void {
    req.url = req.originalUrl.replace('/oidc', '');
    return callback(req, res);
  }
}
```

### to an `express` application
```js
// assumes express ^4.0.0
expressApp.use('/oidc', oidc.callback());
```

### to a `koa` application
```js
// assumes koa ^2.0.0
// assumes koa-mount ^4.0.0
const mount = require('koa-mount');
koaApp.use(mount('/oidc', oidc.app));
```

Note: when the issuer identifier does not include the path prefix you should take care of rewriting
your `${root}/.well-known/openid-configuration` to `${root}${prefix}/.well-known/openid-configuration`
so that your deployment remains conform to the
[Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) specification.

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
| standalone oidc-provider | `provider.proxy = true` |
| oidc-provider mounted to an `express` application | `provider.proxy = true` |
| oidc-provider mounted to a `connect` application | `provider.proxy = true` |
| oidc-provider mounted to a `koa` application | `yourKoaApp.proxy = true` |
| oidc-provider mounted to a `fastify` application | `provider.proxy = true` |
| oidc-provider mounted to a `hapi` application | `provider.proxy = true` |
| oidc-provider mounted to a `nest` application | `provider.proxy = true` |

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

**Table of Contents**

> ❗ marks the configuration you most likely want to take a look at.

- [adapter ❗](#adapter)
- [clients ❗](#clients)
- [findAccount ❗](#findaccount)
- [jwks ❗](#jwks)
- [features ❗](#features)
  - [backchannelLogout](#featuresbackchannellogout)
  - [ciba](#featuresciba)
  - [claimsParameter](#featuresclaimsparameter)
  - [clientCredentials](#featuresclientcredentials)
  - [deviceFlow](#featuresdeviceflow)
  - [devInteractions ❗](#featuresdevinteractions)
  - [dPoP](#featuresdpop)
  - [encryption](#featuresencryption)
  - [fapi](#featuresfapi)
  - [introspection](#featuresintrospection)
  - [jwtIntrospection](#featuresjwtintrospection)
  - [jwtResponseModes](#featuresjwtresponsemodes)
  - [jwtUserinfo](#featuresjwtuserinfo)
  - [mTLS](#featuresmtls)
  - [pushedAuthorizationRequests](#featurespushedauthorizationrequests)
  - [registration](#featuresregistration)
  - [registrationManagement](#featuresregistrationmanagement)
  - [requestObjects](#featuresrequestobjects)
  - [resourceIndicators ❗](#featuresresourceindicators)
  - [revocation](#featuresrevocation)
  - [userinfo](#featuresuserinfo)
- [acrValues](#acrvalues)
- [allowOmittingSingleRegisteredRedirectUri](#allowomittingsingleregisteredredirecturi)
- [claims ❗](#claims)
- [clientBasedCORS](#clientbasedcors)
- [clientDefaults](#clientdefaults)
- [clockTolerance](#clocktolerance)
- [conformIdTokenClaims](#conformidtokenclaims)
- [cookies](#cookies)
- [discovery](#discovery)
- [expiresWithSession](#expireswithsession)
- [extraClientMetadata](#extraclientmetadata)
- [extraParams](#extraparams)
- [extraTokenClaims](#extratokenclaims)
- [httpOptions](#httpoptions)
- [interactions ❗](#interactions)
- [issueRefreshToken](#issuerefreshtoken)
- [loadExistingGrant](#loadexistinggrant)
- [pairwiseIdentifier](#pairwiseidentifier)
- [pkce ❗](#pkce)
- [renderError](#rendererror)
- [responseTypes](#responsetypes)
- [revokeGrantPolicy](#revokegrantpolicy)
- [rotateRefreshToken](#rotaterefreshtoken)
- [routes](#routes)
- [sectorIdentifierUriValidate](#sectoridentifierurivalidate)
- [scopes](#scopes)
- [subjectTypes](#subjecttypes)
- [tokenEndpointAuthMethods](#tokenendpointauthmethods)
- [ttl ❗](#ttl)
- [enabledJWA](#enabledjwa)

<!-- DO NOT EDIT, COMMIT OR STAGE CHANGES BELOW THIS LINE -->
<!-- START CONF OPTIONS -->
### adapter

The provided example and any new instance of oidc-provider will use the basic in-memory adapter for storing issued tokens, codes, user sessions, dynamically registered clients, etc. This is fine as long as you develop, configure and generally just play around since every time you restart your process all information will be lost. As soon as you cannot live with this limitation you will be required to provide your own custom adapter constructor for oidc-provider to use. This constructor will be called for every model accessed the first time it is needed. The API oidc-provider expects is documented [here](/example/my_adapter.js).   
  

<a id="adapter-mongo-db-adapter-implementation"></a><details><summary>(Click to expand) MongoDB adapter implementation</summary><br>


See [/example/adapters/mongodb.js](/example/adapters/mongodb.js)  


</details>
<a id="adapter-redis-adapter-implementation"></a><details><summary>(Click to expand) Redis adapter implementation</summary><br>


See [/example/adapters/redis.js](/example/adapters/redis.js)  


</details>
<a id="adapter-redis-w-re-json-adapter-implementation"></a><details><summary>(Click to expand) Redis w/ ReJSON adapter implementation</summary><br>


See [/example/adapters/redis_rejson.js](/example/adapters/redis_rejson.js)  


</details>
<a id="adapter-default-in-memory-adapter-implementation"></a><details><summary>(Click to expand) Default in-memory adapter implementation</summary><br>


See [/lib/adapters/memory_adapter.js](/lib/adapters/memory_adapter.js)  


</details>

### clients

Array of objects representing client metadata. These clients are referred to as static, they don't expire, never reload, are always available. In addition to these clients the provider will use your adapter's `find` method when a non-static client_id is encountered. If you only wish to support statically configured clients and no dynamic registration then make it so that your adapter resolves client find calls with a falsy value (e.g. `return Promise.resolve()`) and don't take unnecessary DB trips.   
 Client's metadata is validated as defined by the respective specification they've been defined in.   
  


_**default value**_:
```js
[]
```
<a id="clients-available-metadata"></a><details><summary>(Click to expand) Available Metadata</summary><br>


application_type, client_id, client_name, client_secret, client_uri, contacts, default_acr_values, default_max_age, grant_types, id_token_signed_response_alg, initiate_login_uri, jwks, jwks_uri, logo_uri, policy_uri, post_logout_redirect_uris, redirect_uris, require_auth_time, response_types, scope, sector_identifier_uri, subject_type, token_endpoint_auth_method, tos_uri, userinfo_signed_response_alg <br/><br/>The following metadata is available but may not be recognized depending on your provider's configuration.<br/><br/> authorization_encrypted_response_alg, authorization_encrypted_response_enc, authorization_signed_response_alg, backchannel_logout_session_required, backchannel_logout_uri, id_token_encrypted_response_alg, id_token_encrypted_response_enc, introspection_encrypted_response_alg, introspection_encrypted_response_enc, introspection_endpoint_auth_method, introspection_endpoint_auth_signing_alg, introspection_signed_response_alg, request_object_encryption_alg, request_object_encryption_enc, request_object_signing_alg, request_uris, revocation_endpoint_auth_method, revocation_endpoint_auth_signing_alg, tls_client_auth_san_dns, tls_client_auth_san_email, tls_client_auth_san_ip, tls_client_auth_san_uri, tls_client_auth_subject_dn, tls_client_certificate_bound_access_tokens, token_endpoint_auth_signing_alg, userinfo_encrypted_response_alg, userinfo_encrypted_response_enc, web_message_uris  


</details>

### findAccount

Function used to load an account and retrieve its available claims. The return value should be a Promise and #claims() can return a Promise too  


_**default value**_:
```js
async function findAccount(ctx, sub, token) {
  // @param ctx - koa request context
  // @param sub {string} - account identifier (subject)
  // @param token - is a reference to the token used for which a given account is being loaded,
  //   is undefined in scenarios where claims are returned from authorization endpoint
  return {
    accountId: sub,
    // @param use {string} - can either be "id_token" or "userinfo", depending on
    //   where the specific claims are intended to be put in
    // @param scope {string} - the intended scope, while oidc-provider will mask
    //   claims depending on the scope automatically you might want to skip
    //   loading some claims from external resources or through db projection etc. based on this
    //   detail or not return them in ID Tokens but only UserInfo and so on
    // @param claims {object} - the part of the claims authorization parameter for either
    //   "id_token" or "userinfo" (depends on the "use" param)
    // @param rejected {Array[String]} - claim names that were rejected by the end-user, you might
    //   want to skip loading some claims from external resources or through db projection
    async claims(use, scope, claims, rejected) {
      return { sub };
    },
  };
}
```

### jwks

JSON Web Key Set used by the provider for signing and decryption. The object must be in [JWK Set format](https://www.rfc-editor.org/rfc/rfc7517.html#section-5). All provided keys must be private keys.   
 Supported key types are:   
 - RSA
 - OKP (Ed25519, Ed448, X25519, X448 sub types)
 - EC (P-256, secp256k1, P-384, and P-521 curves)   
  

_**recommendation**_: Be sure to follow best practices for distributing private keying material and secrets for your respective target deployment environment.  

_**recommendation**_: The following action order is recommended when rotating signing keys on a distributed deployment with rolling reloads in place.
 1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become available for verification should they be encountered but not yet used for signing
 2. reload all your processes
 3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be used for signing after reload
 4. reload all your processes  


### features

Enable/disable features. Some features are still either based on draft or experimental RFCs. Enabling those will produce a warning in your console and you must be aware that breaking changes may occur between draft implementations and that those will be published as minor versions of oidc-provider. See the example below on how to acknowledge the specification is a draft (this will remove the warning log) and ensure the provider instance will fail to instantiate if a new version of oidc-provider bundles newer version of the RFC with breaking changes in it.   
  

<a id="features-acknowledging-a-draft-experimental-feature"></a><details><summary>(Click to expand) Acknowledging a draft / experimental feature
</summary><br>

```js
new Provider('http://localhost:3000', {
  features: {
    backchannelLogout: {
      enabled: true,
    },
  },
});
// The above code produces this NOTICE
// NOTICE: The following draft features are enabled and their implemented version not acknowledged
// NOTICE:   - OpenID Connect Back-Channel Logout 1.0 - draft 06 (OIDF AB/Connect Working Group draft. URL: https://openid.net/specs/openid-connect-backchannel-1_0-06.html)
// NOTICE: Breaking changes between draft version updates may occur and these will be published as MINOR semver oidc-provider updates.
// NOTICE: You may disable this notice and these potentially breaking updates by acknowledging the current draft version. See https://github.com/panva/node-oidc-provider/tree/v7.3.0/docs/README.md#features
new Provider('http://localhost:3000', {
  features: {
    backchannelLogout: {
      enabled: true,
      ack: 'draft-06', // < we're acknowledging draft 06 of the RFC
    },
  },
});
// No more NOTICE, at this point if the draft implementation changed to 07 and contained no breaking
// changes, you're good to go, still no NOTICE, your code is safe to run.
// Now lets assume you upgrade oidc-provider version and it bundles draft 08 and it contains breaking
// changes
new Provider('http://localhost:3000', {
  features: {
    backchannelLogout: {
      enabled: true,
      ack: 'draft-06', // < bundled is draft-08, but we're still acknowledging draft-06
    },
  },
});
// Thrown:
// Error: An unacknowledged version of a draft feature is included in this oidc-provider version.
```
</details>

### features.backchannelLogout

[Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0-final.html)  

Enables Back-Channel Logout features.  


_**default value**_:
```js
{
  enabled: false
}
```

### features.ciba

[OpenID Connect Client Initiated Backchannel Authentication Flow - Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)  

Enables Core CIBA Flow, when combined with `features.fapi` enables [Financial-grade API: Client Initiated Backchannel Authentication Profile - Implementer's Draft 01](https://openid.net/specs/openid-financial-api-ciba-ID1.html) as well.   
  


_**default value**_:
```js
{
  deliveryModes: [
    'poll'
  ],
  enabled: false,
  processLoginHint: [AsyncFunction: processLoginHint], // see expanded details below
  processLoginHintToken: [AsyncFunction: processLoginHintToken], // see expanded details below
  triggerAuthenticationDevice: [AsyncFunction: triggerAuthenticationDevice], // see expanded details below
  validateBindingMessage: [AsyncFunction: validateBindingMessage], // see expanded details below
  validateRequestContext: [AsyncFunction: validateRequestContext], // see expanded details below
  verifyUserCode: [AsyncFunction: verifyUserCode] // see expanded details below
}
```

<details><summary>(Click to expand) features.ciba options details</summary><br>


#### deliveryModes

Fine-tune the supported token delivery modes. Supported values are
 - `poll`
 - `ping`   
  


_**default value**_:
```js
[
  'poll'
]
```

#### processLoginHint

Helper function used to process the login_hint parameter and return the accountId value to use for processsing the request.   
  

_**recommendation**_: Use `throw Provider.errors.InvalidRequest('validation error message')` when login_hint is invalid.  

_**recommendation**_: Use `return undefined` or when you can't determine the accountId from the login_hint.  


_**default value**_:
```js
async function processLoginHint(ctx, loginHint) {
  // @param ctx - koa request context
  // @param loginHint - string value of the login_hint parameter
  throw new Error('features.ciba.processLoginHint not implemented');
}
```

#### processLoginHintToken

Helper function used to process the login_hint_token parameter and return the accountId value to use for processsing the request.   
  

_**recommendation**_: Use `throw Provider.errors.ExpiredLoginHintToken('validation error message')` when login_hint_token is expired.  

_**recommendation**_: Use `throw Provider.errors.InvalidRequest('validation error message')` when login_hint_token is invalid.  

_**recommendation**_: Use `return undefined` or when you can't determine the accountId from the login_hint.  


_**default value**_:
```js
async function processLoginHintToken(ctx, loginHintToken) {
  // @param ctx - koa request context
  // @param loginHintToken - string value of the login_hint_token parameter
  throw new Error('features.ciba.processLoginHintToken not implemented');
}
```

#### triggerAuthenticationDevice

Helper function used to trigger the authentication and authorization on end-user's Authentication Device. It is called after accepting the backchannel authentication request but before sending client back the response.   
 When the end-user authenticates use `provider.backchannelResult()` to finish the Consumption Device login process.   
  


_**default value**_:
```js
async function triggerAuthenticationDevice(ctx, request, account, client) {
  // @param ctx - koa request context
  // @param request - the BackchannelAuthenticationRequest instance
  // @param account - the account object retrieved by findAccount
  // @param client - the Client instance
  throw new Error('features.ciba.triggerAuthenticationDevice not implemented');
}
```
<a id="trigger-authentication-device-provider-backchannel-result-method"></a><details><summary>(Click to expand) `provider.backchannelResult()` method</summary><br>


`backchannelResult` is a method on the Provider prototype, it returns a `Promise` with no fulfillment value.
  

```js
const provider = new Provider(...);
await provider.backchannelResult(...);
```
`backchannelResult(request, result[, options]);`
 - `request` BackchannelAuthenticationRequest - BackchannelAuthenticationRequest instance.
 - `result` Grant | OIDCProviderError - instance of a persisted Grant model or an OIDCProviderError (all exported by Provider.errors).
 - `options.acr?`: string - Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied.
 - `options.amr?`: string[] - Identifiers for authentication methods used in the authentication.
 - `options.authTime?`: number - Time when the End-User authentication occurred.  


</details>

#### validateBindingMessage

Helper function used to process the binding_message parameter and throw if its not following the authorization server's policy.   
  

_**recommendation**_: Use `throw Provider.errors.InvalidBindingMessage('validation error message')` when the binding_message is invalid.  

_**recommendation**_: Use `return undefined` when a binding_message isn't required and wasn't provided.  


_**default value**_:
```js
async function validateBindingMessage(ctx, bindingMessage) {
  // @param ctx - koa request context
  // @param bindingMessage - string value of the binding_message parameter, when not provided it is undefined
  if (bindingMessage && !/^[a-zA-Z0-9-._+/!?#]{1,20}$/.exec(bindingMessage)) {
    throw new errors.InvalidBindingMessage('the binding_message value, when provided, needs to be 1 - 20 characters in length and use only a basic set of characters (matching the regex: ^[a-zA-Z0-9-._+/!?#]{1,20}$ )');
  }
}
```

#### validateRequestContext

Helper function used to process the request_context parameter and throw if its not following the authorization server's policy.   
  

_**recommendation**_: Use `throw Provider.errors.InvalidRequest('validation error message')` when the request_context is required by policy and missing or invalid.  

_**recommendation**_: Use `return undefined` when a request_context isn't required and wasn't provided.  


_**default value**_:
```js
async function validateRequestContext(ctx, requestContext) {
  // @param ctx - koa request context
  // @param requestContext - string value of the request_context parameter, when not provided it is undefined
  throw new Error('features.ciba.validateRequestContext not implemented');
}
```

#### verifyUserCode

Helper function used to verify the user_code parameter value is present when required and verify its value.   
  

_**recommendation**_: Use `throw Provider.errors.MissingUserCode('validation error message')` when user_code should have been provided but wasn't.  

_**recommendation**_: Use `throw Provider.errors.InvalidUserCode('validation error message')` when the provided user_code is invalid.  

_**recommendation**_: Use `return undefined` when no user_code was provided and isn't required.  


_**default value**_:
```js
async function verifyUserCode(ctx, account, userCode) {
  // @param ctx - koa request context
  // @param account -
  // @param userCode - string value of the user_code parameter, when not provided it is undefined
  throw new Error('features.ciba.verifyUserCode not implemented');
}
```

</details>

### features.claimsParameter

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) - Requesting Claims using the "claims" Request Parameter  

Enables the use and validations of `claims` parameter as described in the specification.   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.clientCredentials

[RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3.4) - Client Credentials  

Enables `grant_type=client_credentials` to be used on the token endpoint.  


_**default value**_:
```js
{
  enabled: false
}
```

### features.dPoP

[draft-ietf-oauth-dpop-03](https://tools.ietf.org/html/draft-ietf-oauth-dpop-03) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (DPoP)  

Enables `DPoP` - mechanism for sender-constraining tokens via a proof-of-possession mechanism on the application level. Browser DPoP Proof generation [here](https://www.npmjs.com/package/dpop).   
  

_**recommendation**_: Updates to draft specification versions are released as MINOR library versions, if you utilize these specification implementations consider using the tilde `~` operator in your package.json since breaking changes may be introduced as part of these version updates. Alternatively, [acknowledge](#features) the version and be notified of breaking changes as part of your CI.  


_**default value**_:
```js
{
  ack: undefined,
  enabled: false,
  iatTolerance: 60
}
```

### features.devInteractions

Development-ONLY out of the box interaction views bundled with the library allow you to skip the boring frontend part while experimenting with oidc-provider. Enter any username (will be used as sub claim value) and any password to proceed.   
 Be sure to disable and replace this feature with your actual frontend flows and End-User authentication flows as soon as possible. These views are not meant to ever be seen by actual users.  


_**default value**_:
```js
{
  enabled: true
}
```

### features.deviceFlow

[RFC8628](https://www.rfc-editor.org/rfc/rfc8628.html) - OAuth 2.0 Device Authorization Grant (Device Flow)  

Enables Device Authorization Grant  


_**default value**_:
```js
{
  charset: 'base-20',
  deviceInfo: [Function: deviceInfo], // see expanded details below
  enabled: false,
  mask: '****-****',
  successSource: [AsyncFunction: successSource], // see expanded details below
  userCodeConfirmSource: [AsyncFunction: userCodeConfirmSource], // see expanded details below
  userCodeInputSource: [AsyncFunction: userCodeInputSource] // see expanded details below
}
```

<details><summary>(Click to expand) features.deviceFlow options details</summary><br>


#### charset

alias for a character set of the generated user codes. Supported values are
 - `base-20` uses BCDFGHJKLMNPQRSTVWXZ
 - `digits` uses 0123456789  


_**default value**_:
```js
'base-20'
```

#### deviceInfo

Function used to extract details from the device authorization endpoint request. This is then available during the end-user confirm screen and is supposed to aid the user confirm that the particular authorization initiated by the user from a device in his possession  


_**default value**_:
```js
function deviceInfo(ctx) {
  return {
    ip: ctx.ip,
    ua: ctx.get('user-agent'),
  };
}
```

#### mask

a string used as a template for the generated user codes, `*` characters will be replaced by random chars from the charset, `-`(dash) and ` ` (space) characters may be included for readability. See the RFC for details about minimal recommended entropy  


_**default value**_:
```js
'****-****'
```

#### successSource

HTML source rendered when device code feature renders a success page for the User-Agent.  


_**default value**_:
```js
async function successSource(ctx) {
  // @param ctx - koa request context
  const {
    clientId, clientName, clientUri, initiateLoginUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client;
  ctx.body = `<!DOCTYPE html>
    <head>
      <title>Sign-in Success</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>Sign-in Success</h1>
        <p>Your sign-in ${clientName ? `with ${clientName}` : ''} was successful, you can now close this page.</p>
      </div>
    </body>
    </html>`;
}
```

#### userCodeConfirmSource

HTML source rendered when device code feature renders an a confirmation prompt for ther User-Agent.  


_**default value**_:
```js
async function userCodeConfirmSource(ctx, form, client, deviceInfo, userCode) {
  // @param ctx - koa request context
  // @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
  //   submitted by the End-User.
  // @param deviceInfo - device information from the device_authorization_endpoint call
  // @param userCode - formatted user code by the configured mask
  const {
    clientId, clientName, clientUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client;
  ctx.body = `<!DOCTYPE html>
    <head>
      <title>Device Login Confirmation</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>Confirm Device</h1>
        <p>
          <strong>${clientName || clientId}</strong>
          <br/><br/>
          The following code should be displayed on your device<br/><br/>
          <code>${userCode}</code>
          <br/><br/>
          <small>If you did not initiate this action, the code does not match or are unaware of such device in your possession please close this window or click abort.</small>
        </p>
        ${form}
        <button autofocus type="submit" form="op.deviceConfirmForm">Continue</button>
        <div>
          <button type="submit" form="op.deviceConfirmForm" value="yes" name="abort">[ Abort ]</button>
        </div>
      </div>
    </body>
    </html>`;
}
```

#### userCodeInputSource

HTML source rendered when device code feature renders an input prompt for the User-Agent.  


_**default value**_:
```js
async function userCodeInputSource(ctx, form, out, err) {
  // @param ctx - koa request context
  // @param form - form source (id="op.deviceInputForm") to be embedded in the page and submitted
  //   by the End-User.
  // @param out - if an error is returned the out object contains details that are fit to be
  //   rendered, i.e. does not include internal error messages
  // @param err - error object with an optional userCode property passed when the form is being
  //   re-rendered due to code missing/invalid/expired
  let msg;
  if (err && (err.userCode || err.name === 'NoCodeError')) {
    msg = '<p>The code you entered is incorrect. Try again</p>';
  } else if (err && err.name === 'AbortedError') {
    msg = '<p>The Sign-in request was interrupted</p>';
  } else if (err) {
    msg = '<p>There was an error processing your request</p>';
  } else {
    msg = '<p>Enter the code displayed on your device</p>';
  }
  ctx.body = `<!DOCTYPE html>
    <head>
      <title>Sign-in</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>Sign-in</h1>
        ${msg}
        ${form}
        <button type="submit" form="op.deviceInputForm">Continue</button>
      </div>
    </body>
    </html>`;
}
```

</details>

### features.encryption

Enables encryption features such as receiving encrypted UserInfo responses, encrypted ID Tokens and allow receiving encrypted Request Objects.  


_**default value**_:
```js
{
  enabled: false
}
```

### features.fapi

Financial-grade API Security Profile  

Enables extra Authorization Server behaviours defined in FAPI that cannot be achieved by other configuration options.   
  


_**default value**_:
```js
{
  enabled: false,
  profile: '1.0 Final'
}
```
<a id="features-fapi-other-configuration-needed-to-reach-fapi-conformance"></a><details><summary>(Click to expand) other configuration needed to reach FAPI conformance
</summary><br>


- `clientDefaults` for setting different default client `token_endpoint_auth_method`
 - `clientDefaults` for setting different default client `id_token_signed_response_alg`
 - `clientDefaults` for setting different default client `response_types`
 - `clientDefaults` for setting client `tls_client_certificate_bound_access_tokens` to true
 - `clientDefaults` for setting client `require_signed_request_object` to true
 - `clientDefaults` for setting client `default_acr_values` to whatever values are set by the specific FAPI ecosystem
 - `features.mTLS` and enable `certificateBoundAccessTokens`
 - `features.mTLS` and enable `selfSignedTlsClientAuth` and/or `tlsClientAuth`
 - `features.claimsParameter`
 - `features.requestObjects` and enable `request` and/or `request_uri`
 - `enabledJWA` algorithm allow lists
 - (optional) `features.pushedAuthorizationRequests`
 - (optional) `features.jwtResponseModes`  


</details>

<details><summary>(Click to expand) features.fapi options details</summary><br>


#### profile

The specific profile of FAPI to enable. Supported values are:   
 - '1.0 Final' (default) Enables behaviours from [Financial-grade API Security Profile 1.0 - Part 2: Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html)
 - '1.0 ID2' Enables behaviours from [Financial-grade API - Part 2: Read and Write API Security Profile - Implementer's Draft 02](https://openid.net/specs/openid-financial-api-part-2-ID2.html)
 - Function returning one of the other supported values, or undefined if FAPI behaviours are to be ignored. The function is invoked with two arguments `(ctx, client)` and serves the purpose of allowing the used profile to be context-specific.  


_**default value**_:
```js
'1.0 Final'
```

</details>

### features.introspection

[RFC7662](https://www.rfc-editor.org/rfc/rfc7662.html) - OAuth 2.0 Token Introspection  

Enables Token Introspection for:
 - opaque access tokens
 - refresh tokens   
  


_**default value**_:
```js
{
  allowedPolicy: [AsyncFunction: introspectionAllowedPolicy], // see expanded details below
  enabled: false
}
```

<details><summary>(Click to expand) features.introspection options details</summary><br>


#### allowedPolicy

Helper function used to determine whether the client/RS (client argument) is allowed to introspect the given token (token argument).  


_**default value**_:
```js
async function introspectionAllowedPolicy(ctx, client, token) {
  if (client.introspectionEndpointAuthMethod === 'none' && token.clientId !== ctx.oidc.client.clientId) {
    return false;
  }
  return true;
}
```

</details>

### features.jwtIntrospection

[draft-ietf-oauth-jwt-introspection-response-10](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-10) - JWT Response for OAuth Token Introspection  

Enables JWT responses for Token Introspection features   
  

_**recommendation**_: Updates to draft specification versions are released as MINOR library versions, if you utilize these specification implementations consider using the tilde `~` operator in your package.json since breaking changes may be introduced as part of these version updates. Alternatively, [acknowledge](#features) the version and be notified of breaking changes as part of your CI.  


_**default value**_:
```js
{
  ack: undefined,
  enabled: false
}
```

### features.jwtResponseModes

[JWT Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html)  

Enables JWT Secured Authorization Responses  


_**default value**_:
```js
{
  enabled: false
}
```

### features.jwtUserinfo

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - JWT UserInfo Endpoint Responses  

Enables the userinfo to optionally return signed and/or encrypted JWTs, also enables the relevant client metadata for setting up signing and/or encryption.  


_**default value**_:
```js
{
  enabled: false
}
```

### features.mTLS

[RFC8705](https://www.rfc-editor.org/rfc/rfc8705.html) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens (MTLS)  

Enables specific features from the Mutual TLS specification. The three main features have their own specific setting in this feature's configuration object and you must provide functions for resolving some of the functions which are deployment-specific.   
  


_**default value**_:
```js
{
  certificateAuthorized: [Function: certificateAuthorized], // see expanded details below
  certificateBoundAccessTokens: false,
  certificateSubjectMatches: [Function: certificateSubjectMatches], // see expanded details below
  enabled: false,
  getCertificate: [Function: getCertificate], // see expanded details below
  selfSignedTlsClientAuth: false,
  tlsClientAuth: false
}
```

<details><summary>(Click to expand) features.mTLS options details</summary><br>


#### certificateAuthorized

Function used to determine if the client certificate, used in the request, is verified and comes from a trusted CA for the client. Should return true/false. Only used for `tls_client_auth` client authentication method.   
  

<a id="certificate-authorized-when-behind-a-tls-terminating-proxy-nginx-apache"></a><details><summary>(Click to expand) When behind a TLS terminating proxy (nginx/apache)</summary><br>


When behind a TLS terminating proxy it is common that this detail be passed to the application as a sanitized header. This returns the chosen header value provided by nginx's `$ssl_client_verify` or apache's `%{SSL_CLIENT_VERIFY}s`
  

```js
function certificateAuthorized(ctx) {
  return ctx.get('x-ssl-client-verify') === 'SUCCESS';
}
```
</details>
<a id="certificate-authorized-when-using-node's-https-create-server"></a><details><summary>(Click to expand) When using node's `https.createServer`
</summary><br>

```js
function certificateAuthorized(ctx) {
  return ctx.socket.authorized;
}
```
</details>

#### certificateBoundAccessTokens

Enables section 3 & 4 Mutual TLS Client Certificate-Bound Tokens by exposing the client's `tls_client_certificate_bound_access_tokens` metadata property.  


_**default value**_:
```js
false
```

#### certificateSubjectMatches

Function used to determine if the client certificate, used in the request, subject matches the registered client property. Only used for `tls_client_auth` client authentication method.   
  

<a id="certificate-subject-matches-when-behind-a-tls-terminating-proxy-nginx-apache"></a><details><summary>(Click to expand) When behind a TLS terminating proxy (nginx/apache)</summary><br>


TLS terminating proxies can pass a header with the Subject DN pretty easily, for Nginx this would be `$ssl_client_s_dn`, for apache `%{SSL_CLIENT_S_DN}s`.
  

```js
function certificateSubjectMatches(ctx, property, expected) {
  switch (property) {
    case 'tls_client_auth_subject_dn':
      return ctx.get('x-ssl-client-s-dn') === expected;
    default:
      throw new Error(`${property} certificate subject matching not implemented`);
  }
}
```
</details>

#### getCertificate

Function used to retrieve the PEM-formatted client certificate used in the request.   
  

<a id="get-certificate-when-behind-a-tls-terminating-proxy-nginx-apache"></a><details><summary>(Click to expand) When behind a TLS terminating proxy (nginx/apache)</summary><br>


When behind a TLS terminating proxy it is common that the certificate be passed to the application as a sanitized header. This returns the chosen header value provided by nginx's `$ssl_client_cert` or apache's `%{SSL_CLIENT_CERT}s`
  

```js
function getCertificate(ctx) {
  return ctx.get('x-ssl-client-cert');
}
```
</details>
<a id="get-certificate-when-using-node's-https-create-server"></a><details><summary>(Click to expand) When using node's `https.createServer`
</summary><br>

```js
function getCertificate(ctx) {
  const peerCertificate = ctx.socket.getPeerCertificate();
  if (peerCertificate.raw) {
    return `-----BEGIN CERTIFICATE-----\n${peerCertificate.raw.toString('base64')}\n-----END CERTIFICATE-----`;
  }
}
```
</details>

#### selfSignedTlsClientAuth

Enables section 2.2. Self-Signed Certificate Mutual TLS client authentication method `self_signed_tls_client_auth` for use in the server's `tokenEndpointAuthMethods` configuration.  


_**default value**_:
```js
false
```

#### tlsClientAuth

Enables section 2.1. PKI Mutual TLS client authentication method `tls_client_auth` for use in the server's `tokenEndpointAuthMethods` configuration.  


_**default value**_:
```js
false
```

</details>

### features.pushedAuthorizationRequests

[RFC9126](https://www.rfc-editor.org/rfc/rfc9126.html) - OAuth 2.0 Pushed Authorization Requests (PAR)  

Enables the use of `pushed_authorization_request_endpoint` defined by the Pushed Authorization Requests RFC.  


_**default value**_:
```js
{
  enabled: false,
  requirePushedAuthorizationRequests: false
}
```

<details><summary>(Click to expand) features.pushedAuthorizationRequests options details</summary><br>


#### requirePushedAuthorizationRequests

Makes the use of PAR required for all authorization requests as an OP policy.  


_**default value**_:
```js
false
```

</details>

### features.registration

[Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)  

Enables Dynamic Client Registration.  


_**default value**_:
```js
{
  enabled: false,
  idFactory: [Function: idFactory], // see expanded details below
  initialAccessToken: false,
  issueRegistrationAccessToken: true,
  policies: undefined,
  secretFactory: [AsyncFunction: secretFactory] // see expanded details below
}
```

<details><summary>(Click to expand) features.registration options details</summary><br>


#### idFactory

Function used to generate random client identifiers during dynamic client registration  


_**default value**_:
```js
function idFactory(ctx) {
  return nanoid();
}
```

#### initialAccessToken

Enables registration_endpoint to check a valid initial access token is provided as a bearer token during the registration call. Supported types are
 - `string` the string value will be checked as a static initial access token
 - `boolean` true/false to enable/disable adapter backed initial access tokens   
  


_**default value**_:
```js
false
```
<a id="initial-access-token-to-add-an-adapter-backed-initial-access-token-and-retrive-its-value"></a><details><summary>(Click to expand) To add an adapter backed initial access token and retrive its value
</summary><br>

```js
new (provider.InitialAccessToken)({}).save().then(console.log);
```
</details>

#### issueRegistrationAccessToken

Boolean or a function used to decide whether a registration access token will be issued or not. Supported values are
 - `true` registration access tokens is issued
 - `false` registration access tokens is not issued
 - function returning true/false, true when token should be issued, false when it shouldn't   
  


_**default value**_:
```js
true
```
<a id="issue-registration-access-token-to-determine-if-a-registration-access-token-should-be-issued-dynamically"></a><details><summary>(Click to expand) To determine if a registration access token should be issued dynamically
</summary><br>

```js
// @param ctx - koa request context
async issueRegistrationAccessToken(ctx) {
  return policyImplementation(ctx)
}
```
</details>

#### policies

define registration and registration management policies applied to client properties. Policies are sync/async functions that are assigned to an Initial Access Token that run before the regular client property validations are run. Multiple policies may be assigned to an Initial Access Token and by default the same policies will transfer over to the Registration Access Token. A policy may throw / reject and it may modify the properties object.   
  

_**recommendation**_: referenced policies must always be present when encountered on a token, an AssertionError will be thrown inside the request context if it is not, resulting in a 500 Server Error.  

_**recommendation**_: the same policies will be assigned to the Registration Access Token after a successful validation. If you wish to assign different policies to the Registration Access Token
 ```js
 // inside your final ran policy
 ctx.oidc.entities.RegistrationAccessToken.policies = ['update-policy'];
 ```  


_**default value**_:
```js
undefined
```
<a id="policies-to-define-registration-and-registration-management-policies"></a><details><summary>(Click to expand) To define registration and registration management policies</summary><br>


To define policy functions configure `features.registration` to be an object like so:
  

```js
{
  enabled: true,
  initialAccessToken: true, // to enable adapter-backed initial access tokens
  policies: {
    'my-policy': function (ctx, properties) {
      // @param ctx - koa request context
      // @param properties - the client properties which are about to be validated
      // example of setting a default
      if (!('client_name' in properties)) {
        properties.client_name = generateRandomClientName();
      }
      // example of forcing a value
      properties.userinfo_signed_response_alg = 'RS256';
      // example of throwing a validation error
      if (someCondition(ctx, properties)) {
        throw new Provider.errors.InvalidClientMetadata('validation error message');
      }
    },
    'my-policy-2': async function (ctx, properties) {},
  },
}
```
An Initial Access Token with those policies being executed (one by one in that order) is created like so
  

```js
new (provider.InitialAccessToken)({ policies: ['my-policy', 'my-policy-2'] }).save().then(console.log);
```
</details>

#### secretFactory

Function used to generate random client secrets during dynamic client registration  


_**default value**_:
```js
async function secretFactory(ctx) {
  const bytes = Buffer.allocUnsafe(64);
  await randomFill(bytes);
  return base64url.encodeBuffer(bytes);
}
```

</details>

### features.registrationManagement

[OAuth 2.0 Dynamic Client Registration Management Protocol](https://www.rfc-editor.org/rfc/rfc7592.html)  

Enables Update and Delete features described in the RFC  


_**default value**_:
```js
{
  enabled: false,
  rotateRegistrationAccessToken: false
}
```

<details><summary>(Click to expand) features.registrationManagement options details</summary><br>


#### rotateRegistrationAccessToken

Enables registration access token rotation. The provider will discard the current Registration Access Token with a successful update and issue a new one, returning it to the client with the Registration Update Response. Supported values are
 - `false` registration access tokens are not rotated
 - `true` registration access tokens are rotated when used
 - function returning true/false, true when rotation should occur, false when it shouldn't  


_**default value**_:
```js
false
```
<a id="rotate-registration-access-token-function-use"></a><details><summary>(Click to expand) function use
</summary><br>

```js
{
  features: {
    registrationManagement: {
      enabled: true,
      async rotateRegistrationAccessToken(ctx) {
        // return tokenRecentlyRotated(ctx.oidc.entities.RegistrationAccessToken);
        // or
        // return customClientBasedPolicy(ctx.oidc.entities.Client);
      }
    }
  }
}
```
</details>

</details>

### features.requestObjects

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject) and [JWT Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html) - Request Object  

Enables the use and validations of the `request` and/or `request_uri` parameters.  


_**default value**_:
```js
{
  mode: 'lax',
  request: false,
  requestUri: true,
  requireSignedRequestObject: false,
  requireUriRegistration: true
}
```

<details><summary>(Click to expand) features.requestObjects options details</summary><br>


#### mode

defines the provider's strategy when it comes to using regular OAuth 2.0 parameters that are present. Parameters inside the Request Object are ALWAYS used, this option controls whether to combine those with the regular ones or not.   
 Supported values are:   
 - 'lax' (default) This is the behaviour expected by OIDC Core 1.0 - all parameters that are not present in the Resource Object are used when resolving the authorization request.
 - 'strict' This is the behaviour expected by FAPI or JAR, all parameters outside of the Request Object are ignored. For FAPI and FAPI-CIBA this value is enforced.   
  


_**default value**_:
```js
'lax'
```

#### request

Enables the use and validations of the `request` parameter.  


_**default value**_:
```js
false
```

#### requestUri

Enables the use and validations of the `request_uri` parameter.  


_**default value**_:
```js
true
```

#### requireSignedRequestObject

Makes the use of signed request objects required for all authorization requests as an OP policy.  


_**default value**_:
```js
false
```

#### requireUriRegistration

Makes request_uri pre-registration mandatory (true) or optional (false).  


_**default value**_:
```js
true
```

</details>

### features.resourceIndicators

[RFC8707](https://www.rfc-editor.org/rfc/rfc8707.html) - Resource Indicators for OAuth 2.0  

Enables the use of `resource` parameter for the authorization and token endpoints to enable issuing Access Tokens for Resource Servers (APIs).   
 - Multiple resource parameters may be present during Authorization Code Flow, Device Authorization Grant, and Backchannel Authentication Requests, but only a single audience for an Access Token is permitted.
 - Authorization and Authentication Requests that result in an Access Token being issued by the Authorization Endpoint must only contain a single resource (or one must be resolved using the `defaultResource` helper).
 - Client Credentials grant must only contain a single resource parameter.
 - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request exchanges, if the exchanged code/token does not include the `'openid'` scope and only has a single resource then the resource parameter may be omitted - an Access Token for the single resource is returned.
 - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request exchanges, if the exchanged code/token does not include the `'openid'` scope and has multiple resources then the resource parameter must be provided (or one must be resolved using the `defaultResource` helper). An Access Token for the provided/resolved resource is returned.
 - (with userinfo endpoint enabled and useGrantedResource helper returning falsy) During Authorization Code / Refresh Token / Device Code exchanges, if the exchanged code/token includes the `'openid'` scope and no resource parameter is present - an Access Token for the UserInfo Endpoint is returned.
 - (with userinfo endpoint enabled and useGrantedResource helper returning truthy) During Authorization Code / Refresh Token / Device Code exchanges, even if the exchanged code/token includes the `'openid'` scope and only has a single resource then the resource parameter may be omitted - an Access Token for the single resource is returned.
 - (with userinfo endpoint disabled) During Authorization Code / Refresh Token / Device Code exchanges, if the exchanged code/token includes the `'openid'` scope and only has a single resource then the resource parameter may be omitted - an Access Token for the single resource is returned.
 - Issued Access Tokens always only contain scopes that are defined on the respective Resource Server (returned from `features.resourceIndicators.getResourceServerInfo`).  


_**default value**_:
```js
{
  defaultResource: [AsyncFunction: defaultResource], // see expanded details below
  enabled: true,
  getResourceServerInfo: [AsyncFunction: getResourceServerInfo], // see expanded details below
  useGrantedResource: [AsyncFunction: useGrantedResource] // see expanded details below
}
```

<details><summary>(Click to expand) features.resourceIndicators options details</summary><br>


#### defaultResource

Function used to determine the default resource indicator for a request when none is provided by the client during the authorization request or when multiple are provided/resolved and only a single one is required during an Access Token Request.  


_**default value**_:
```js
async function defaultResource(ctx, client, oneOf) {
  // @param ctx - koa request context
  // @param client - client making the request
  // @param oneOf {string[]} - The OP needs to select **one** of the values provided.
  //                           Default is that the array is provided so that the request will fail.
  //                           This argument is only provided when called during
  //                           Authorization Code / Refresh Token / Device Code exchanges.
  if (oneOf) return oneOf;
  return undefined;
}
```

#### getResourceServerInfo

Function used to load information about a Resource Server (API) and check if the client is meant to request scopes for that particular resource.   
  

_**recommendation**_: Only allow client's pre-registered resource values, to pre-register these you shall use the `extraClientMetadata` configuration option to define a custom metadata and use that to implement your policy using this function.  


_**default value**_:
```js
async function getResourceServerInfo(ctx, resourceIndicator, client) {
  // @param ctx - koa request context
  // @param resourceIndicator - resource indicator value either requested or resolved by the defaultResource helper.
  // @param client - client making the request
  throw new errors.InvalidTarget();
}
```
<a id="get-resource-server-info-resource-server-api-with-two-scopes-an-expected-audience-value-an-access-token-ttl-and-a-jwt-access-token-format"></a><details><summary>(Click to expand) Resource Server (API) with two scopes, an expected audience value, an Access Token TTL and a JWT Access Token Format.
</summary><br>

```js
{
  scope: 'api:read api:write',
  audience: 'resource-server-audience-value',
  accessTokenTTL: 2 * 60 * 60, // 2 hours
  accessTokenFormat: 'jwt',
  jwt: {
    sign: { alg: 'ES256' },
  },
}
```
</details>
<a id="get-resource-server-info-resource-server-api-with-two-scopes-and-a-symmetrically-encrypted-jwt-access-token-format"></a><details><summary>(Click to expand) Resource Server (API) with two scopes and a symmetrically encrypted JWT Access Token Format.
</summary><br>

```js
{
  scope: 'api:read api:write',
  accessTokenFormat: 'jwt',
  jwt: {
    sign: false,
    encrypt: {
      alg: 'dir',
      enc: 'A128CBC-HS256',
      key: Buffer.from('f40dd9591646bebcb9c32aed02f5e610c2d15e1d38cde0c1fe14a55cf6bfe2d9', 'hex')
    },
  }
}
```
</details>
<a id="get-resource-server-info-resource-server-api-with-two-scopes-and-a-v-1-local-paseto-access-token-format"></a><details><summary>(Click to expand) Resource Server (API) with two scopes and a v1.local PASETO Access Token Format.
</summary><br>

```js
{
  scope: 'api:read api:write',
  accessTokenFormat: 'paseto',
  paseto: {
    version: 1,
    purpose: 'local',
    key: Buffer.from('f40dd9591646bebcb9c32aed02f5e610c2d15e1d38cde0c1fe14a55cf6bfe2d9', 'hex')
  }
}
```
</details>
<a id="get-resource-server-info-resource-server-definition"></a><details><summary>(Click to expand) Resource Server Definition
</summary><br>

```js
{
  // REQUIRED
  // available scope values (space-delimited string)
  scope: string,
  // OPTIONAL
  // "aud" (Audience) value to use
  // Default is the resource indicator value will be used as token audience
  audience?: string,
  // OPTIONAL
  // Issued Token TTL
  // Default is - see `ttl` configuration
  accessTokenTTL?: number,
  // Issued Token Format
  // Default is - opaque
  accessTokenFormat?: 'opaque' | 'jwt' | 'paseto',
  // JWT Access Token Format (when accessTokenFormat is 'jwt')
  // Default is `{ sign: { alg: 'RS256' }, encrypt: false }`
  // Tokens may be signed, signed and then encrypted, or just encrypted JWTs.
  jwt?: {
    // Tokens will be signed
    sign?:
     | {
         alg?: string, // 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES256K' | 'ES384' | 'ES512' | 'EdDSA' | 'RS256' | 'RS384' | 'RS512'
         kid?: string, // OPTIONAL `kid` to aid in signing key selection
       }
     | {
         alg: string, // 'HS256' | 'HS384' | 'HS512'
         key: crypto.KeyObject | Buffer, // shared symmetric secret to sign the JWT token with
         kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWS Header
       },
    // Tokens will be encrypted
    encrypt?: {
      alg: string, // 'dir' | 'RSA-OAEP' | 'RSA-OAEP-256' | 'RSA-OAEP-384' | 'RSA-OAEP-512' | 'RSA1_5' | 'ECDH-ES' | 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW' | 'A128KW' | 'A192KW' | 'A256KW' | 'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW' | 'PBES2-HS256+A128KW' | 'PBES2-HS384+A192KW' | 'PBES2-HS512+A256KW'
      enc: string, // 'A128CBC-HS256' | 'A128GCM' | 'A192CBC-HS384' | 'A192GCM' | 'A256CBC-HS512' | 'A256GCM'
      key: crypto.KeyObject | Buffer, // public key or shared symmetric secret to encrypt the JWT token with
      kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWE Header
    }
  }
  // PASETO Access Token Format (when accessTokenFormat is 'paseto')
  // Note: v2.local and v4.local are NOT supported
  paseto?: {
    version: 1 | 2 | 3 | 4,
    purpose: 'local' | 'public',
    key?: crypto.KeyObject, // required when purpose is 'local'
    kid?: string, // OPTIONAL `kid` to aid in signing key selection or to put in the footer for 'local'
  }
}
```
</details>

#### useGrantedResource

Function used to determine if an already granted resource indicator should be used without being explicitly requested by the client during the Token Endpoint request.   
  

_**recommendation**_: Use `return true` when it's allowed for a client skip providing the "resource" parameter at the Token Endpoint.  

_**recommendation**_: Use `return false` (default) when it's required for a client to explitly provide a "resource" parameter at the Token Endpoint or when other indication dictates an Access Token for the UserInfo Endpoint should returned.  


_**default value**_:
```js
async function useGrantedResource(ctx, model) {
  // @param ctx - koa request context
  // @param model - depending on the request's grant_type this can be either an AuthorizationCode, BackchannelAuthenticationRequest,
  //                RefreshToken, or DeviceCode model instance.
  return false;
}
```

</details>

### features.revocation

[RFC7009](https://www.rfc-editor.org/rfc/rfc7009.html) - OAuth 2.0 Token Revocation  

Enables Token Revocation for:
 - opaque access tokens
 - refresh tokens   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.rpInitiatedLogout

[RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html)  

Enables RP-Initiated Logout features  


_**default value**_:
```js
{
  enabled: true,
  logoutSource: [AsyncFunction: logoutSource], // see expanded details below
  postLogoutSuccessSource: [AsyncFunction: postLogoutSuccessSource] // see expanded details below
}
```

<details><summary>(Click to expand) features.rpInitiatedLogout options details</summary><br>


#### logoutSource

HTML source rendered when RP-Initiated Logout renders a confirmation prompt for the User-Agent.  


_**default value**_:
```js
async function logoutSource(ctx, form) {
  // @param ctx - koa request context
  // @param form - form source (id="op.logoutForm") to be embedded in the page and submitted by
  //   the End-User
  ctx.body = `<!DOCTYPE html>
    <head>
      <title>Logout Request</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>Do you want to sign-out from ${ctx.host}?</h1>
        ${form}
        <button autofocus type="submit" form="op.logoutForm" value="yes" name="logout">Yes, sign me out</button>
        <button type="submit" form="op.logoutForm">No, stay signed in</button>
      </div>
    </body>
    </html>`;
}
```

#### postLogoutSuccessSource

HTML source rendered when RP-Initiated Logout concludes a logout but there was no `post_logout_redirect_uri` provided by the client.  


_**default value**_:
```js
async function postLogoutSuccessSource(ctx) {
  // @param ctx - koa request context
  const {
    clientId, clientName, clientUri, initiateLoginUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client || {}; // client is defined if the user chose to stay logged in with the OP
  const display = clientName || clientId;
  ctx.body = `<!DOCTYPE html>
    <head>
      <title>Sign-out Success</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>Sign-out Success</h1>
        <p>Your sign-out ${display ? `with ${display}` : ''} was successful.</p>
      </div>
    </body>
    </html>`;
}
```

</details>

### features.userinfo

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - UserInfo Endpoint  

Enables the userinfo endpoint. Its use requires an opaque Access Token with at least `openid` scope that's without a Resource Server audience.  


_**default value**_:
```js
{
  enabled: true
}
```

### acceptQueryParamAccessTokens

Several OAuth 2.0 / OIDC profiles prohibit the use of query strings to carry access tokens. This setting either allows (true) or prohibits (false) that mechanism to be used.   
  


_**default value**_:
```js
true
```

### acrValues

Array of strings, the Authentication Context Class References that the OP supports.  


_**default value**_:
```js
[]
```

### allowOmittingSingleRegisteredRedirectUri

Allow omitting the redirect_uri parameter when only a single one is registered for a client.  


_**default value**_:
```js
false
```

### claims

Describes the claims that the OpenID Provider MAY be able to supply values for.   
 It is used to achieve two different things related to claims:
 - which additional claims are available to RPs (configure as `{ claimName: null }`)
 - which claims fall under what scope (configure `{ scopeName: ['claim', 'another-claim'] }`)   
  


_**default value**_:
```js
{
  acr: null,
  auth_time: null,
  iss: null,
  openid: [
    'sub'
  ],
  sid: null
}
```
<a id="claims-open-id-connect-1-0-standard-claims"></a><details><summary>(Click to expand) OpenID Connect 1.0 Standard Claims</summary><br>


See [/recipes/claim_configuration.md](/recipes/claim_configuration.md)  


</details>

### clientBasedCORS

Function used to check whether a given CORS request should be allowed based on the request's client.   
  


_**default value**_:
```js
function clientBasedCORS(ctx, origin, client) {
  return false;
}
```
<a id="client-based-cors-client-metadata-based-cors-origin-allow-list"></a><details><summary>(Click to expand) Client Metadata-based CORS Origin allow list</summary><br>


See [/recipes/client_based_origins.md](/recipes/client_based_origins.md)  


</details>

### clientDefaults

Default client metadata to be assigned when unspecified by the client metadata, e.g. During Dynamic Client Registration or for statically configured clients. The default value does not represent all default values, but merely copies its subset. You can provide any used client metadata property in this object.   
  


_**default value**_:
```js
{
  grant_types: [
    'authorization_code'
  ],
  id_token_signed_response_alg: 'RS256',
  response_types: [
    'code'
  ],
  token_endpoint_auth_method: 'client_secret_basic'
}
```
<a id="client-defaults-changing-the-default-client-token-endpoint-auth-method"></a><details><summary>(Click to expand) Changing the default client token_endpoint_auth_method</summary><br>


To change the default client token_endpoint_auth_method configure `clientDefaults` to be an object like so:
  

```js
{
  token_endpoint_auth_method: 'client_secret_post'
}
```
</details>
<a id="client-defaults-changing-the-default-client-response-type-to-code-id-token"></a><details><summary>(Click to expand) Changing the default client response type to `code id_token`</summary><br>


To change the default client response_types configure `clientDefaults` to be an object like so:
  

```js
{
  response_types: ['code id_token'],
  grant_types: ['authorization_code', 'implicit'],
}
```
</details>

### clockTolerance

A `Number` value (in seconds) describing the allowed system clock skew for validating client-provided JWTs, e.g. Request Objects, DPoP Proofs and otherwise comparing timestamps  

_**recommendation**_: Only set this to a reasonable value when needed to cover server-side client and oidc-provider server clock skew.  


_**default value**_:
```js
0
```

### conformIdTokenClaims

ID Token only contains End-User claims when the requested `response_type` is `id_token`  

[Core 1.0 - Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) defines that claims requested using the `scope` parameter are only returned from the UserInfo Endpoint unless the `response_type` is `id_token`.   
 Despite of this configuration the ID Token always includes claims requested using the `scope` parameter when the userinfo endpoint is disabled, or when issuing an Access Token not applicable for access to the userinfo endpoint.   
  


_**default value**_:
```js
true
```

### cookies

Options for the [cookie module](https://github.com/pillarjs/cookies#cookiesset-name--value---options--) used to keep track of various User-Agent states. The options `maxAge` and `expires` are ignored. Use `ttl.Session` and `ttl.Interaction` to configure the ttl and in turn the cookie expiration values for Session and Interaction models.  


### cookies.keys

[Keygrip](https://www.npmjs.com/package/keygrip) Signing keys used for cookie signing to prevent tampering.  

_**recommendation**_: Rotate regularly (by prepending new keys) with a reasonable interval and keep a reasonable history of keys to allow for returning user session cookies to still be valid and re-signed  


_**default value**_:
```js
[]
```

### cookies.long

Options for long-term cookies  

_**recommendation**_: set cookies.keys and cookies.long.signed = true  


_**default value**_:
```js
{
  httpOnly: true,
  overwrite: true,
  sameSite: 'none'
}
```

### cookies.names

Cookie names used to store and transfer various states.  


_**default value**_:
```js
{
  interaction: '_interaction',
  resume: '_interaction_resume',
  session: '_session'
}
```

### cookies.short

Options for short-term cookies  

_**recommendation**_: set cookies.keys and cookies.short.signed = true  


_**default value**_:
```js
{
  httpOnly: true,
  overwrite: true,
  sameSite: 'lax'
}
```

### discovery

Pass additional properties to this object to extend the discovery document  


_**default value**_:
```js
{
  claim_types_supported: [
    'normal'
  ],
  claims_locales_supported: undefined,
  display_values_supported: undefined,
  op_policy_uri: undefined,
  op_tos_uri: undefined,
  service_documentation: undefined,
  ui_locales_supported: undefined
}
```

### expiresWithSession

Function used to decide whether the given authorization code/ device code or implicit returned access token be bound to the user session. This will be applied to all tokens issued from the authorization / device code in the future. When tokens are session-bound the session will be loaded by its `uid` every time the token is encountered. Session bound tokens will effectively get revoked if the end-user logs out.  


_**default value**_:
```js
async function expiresWithSession(ctx, token) {
  return !token.scopes.has('offline_access');
}
```

### extraClientMetadata

Allows for custom client metadata to be defined, validated, manipulated as well as for existing property validations to be extended. Existing properties are snakeCased on a Client instance (e.g. `client.redirectUris`), new properties (defined by this configuration) will be avaialable with their names verbatim (e.g. `client['urn:example:client:my-property']`)  


### extraClientMetadata.properties

Array of property names that clients will be allowed to have defined.  


_**default value**_:
```js
[]
```

### extraClientMetadata.validator

validator function that will be executed in order once for every property defined in `extraClientMetadata.properties`, regardless of its value or presence on the client metadata passed in. Must be synchronous, async validators or functions returning Promise will be rejected during runtime. To modify the current client metadata values (for current key or any other) just modify the passed in `metadata` argument.  


_**default value**_:
```js
function extraClientMetadataValidator(ctx, key, value, metadata) {
  // @param ctx - koa request context (only provided when a client is being constructed during
  //              Client Registration Request or Client Update Request
  // @param key - the client metadata property name
  // @param value - the property value
  // @param metadata - the current accumulated client metadata
  // @param ctx - koa request context (only provided when a client is being constructed during
  //              Client Registration Request or Client Update Request
  // validations for key, value, other related metadata
  // throw new Provider.errors.InvalidClientMetadata() to reject the client metadata
  // metadata[key] = value; to (re)assign metadata values
  // return not necessary, metadata is already a reference
}
```

### extraParams

Pass an iterable object (i.e. Array or Set of strings) to extend the parameters recognised by the authorization, device authorization, and pushed authorization request endpoints. These parameters are then available in `ctx.oidc.params` as well as passed to interaction session details.  


_**default value**_:
```js
[]
```

### extraTokenClaims

Function used to assign additional claims to an Access Token when it is being issued. For `opaque` Access Tokens these claims will be stored in your storage under the `extra` property and returned by introspection as top level claims. For `jwt` or `paseto` Access Tokens these will be top level claims. Returned claims will not overwrite pre-existing top level claims.   
  


_**default value**_:
```js
async function extraTokenClaims(ctx, token) {
  return undefined;
}
```
<a id="extra-token-claims-to-push-additional-claims-to-an-access-token"></a><details><summary>(Click to expand) To push additional claims to an Access Token
</summary><br>

```js
{
  extraTokenClaims(ctx, token) {
    return {
      'urn:oidc-provider:example:foo': 'bar',
    };
  }
}
```
</details>

### formats.bitsOfOpaqueRandomness

The value should be an integer (or a function returning an integer) and the resulting opaque token length is equal to `Math.ceil(i / Math.log2(n))` where n is the number of symbols in the used alphabet, 64 in our case.   
  


_**default value**_:
```js
256
```
<a id="formats-bits-of-opaque-randomness-to-have-e-g-refresh-tokens-values-longer-than-access-tokens"></a><details><summary>(Click to expand) To have e.g. Refresh Tokens values longer than Access Tokens.
</summary><br>

```js
function bitsOfOpaqueRandomness(ctx, token) {
  if (token.kind === 'RefreshToken') {
    return 384;
  }
  return 256;
}
```
</details>

### formats.customizers

Customizer functions used before issuing a structured Access Token.   
  


_**default value**_:
```js
{
  jwt: undefined,
  paseto: undefined
}
```
<a id="formats-customizers-to-push-additional-headers-and-payload-claims-to-a-jwt-format-access-token"></a><details><summary>(Click to expand) To push additional headers and payload claims to a `jwt` format Access Token
</summary><br>

```js
{
  customizers: {
    async jwt(ctx, token, jwt) {
      jwt.header = { foo: 'bar' };
      jwt.payload.foo = 'bar';
    }
  }
}
```
</details>
<a id="formats-customizers-to-push-a-payload-a-footer-and-use-an-implicit-assertion-with-a-paseto-structured-access-token"></a><details><summary>(Click to expand) To push a payload, a footer, and use an implicit assertion with a PASETO structured access token
</summary><br>

```js
{
  customizers: {
    paseto(ctx, token, structuredToken) {
      structuredToken.payload.foo = 'bar';
      structuredToken.footer = { foo: 'bar' };
      structuredToken.assertion = 'foo'; // v3 and v4 tokens only
    }
  }
}
```
</details>

### httpOptions

Function called whenever calls to an external HTTP(S) resource are being made. You can change the request `timeout` duration, the `agent` used as well as the `lookup` resolver function.   
  


_**default value**_:
```js
function httpOptions(url) {
  return {
    timeout: 2500,
    agent: undefined, // defaults to node's global agents (https.globalAgent or http.globalAgent)
    lookup: undefined, // defaults to CacheableLookup (https://github.com/szmarczak/cacheable-lookup)
  };
}
```
<a id="http-options-to-change-the-request's-timeout"></a><details><summary>(Click to expand) To change the request's timeout</summary><br>


To change all request's timeout configure the httpOptions as a function like so:
  

```js
 {
   httpOptions(url) {
     return { timeout: 5000 };
   }
 }
```
</details>

### interactions

Holds the configuration for interaction policy and url to send end-users to when the policy decides to require interaction.   
  


### interactions.policy

structure of Prompts and their checks formed by Prompt and Check class instances. The default you can get a fresh instance for and the classes are available under `Provider.interactionPolicy`.   
  


_**default value**_:
```js
[
/* LOGIN PROMPT */
new Prompt(
  { name: 'login', requestable: true },

  (ctx) => {
    const { oidc } = ctx;

    return {
      ...(oidc.params.max_age === undefined ? undefined : { max_age: oidc.params.max_age }),
      ...(oidc.params.login_hint === undefined ? undefined : { login_hint: oidc.params.login_hint }),
      ...(oidc.params.id_token_hint === undefined ? undefined : { id_token_hint: oidc.params.id_token_hint }),
    };
  },

  new Check('no_session', 'End-User authentication is required', (ctx) => {
    const { oidc } = ctx;
    if (oidc.session.accountId) {
      return Check.NO_NEED_TO_PROMPT;
    }

    return Check.REQUEST_PROMPT;
  }),

  new Check('max_age', 'End-User authentication could not be obtained', (ctx) => {
    const { oidc } = ctx;
    if (oidc.params.max_age === undefined) {
      return Check.NO_NEED_TO_PROMPT;
    }

    if (!oidc.session.accountId) {
      return Check.REQUEST_PROMPT;
    }

    if (oidc.session.past(oidc.params.max_age) && (!ctx.oidc.result || !ctx.oidc.result.login)) {
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }),

  new Check('id_token_hint', 'id_token_hint and authenticated subject do not match', async (ctx) => {
    const { oidc } = ctx;
    if (oidc.entities.IdTokenHint === undefined) {
      return Check.NO_NEED_TO_PROMPT;
    }

    const { payload } = oidc.entities.IdTokenHint;

    let sub = oidc.session.accountId;
    if (sub === undefined) {
      return Check.REQUEST_PROMPT;
    }

    if (oidc.client.subjectType === 'pairwise') {
      sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(ctx, sub, oidc.client);
    }

    if (payload.sub !== sub) {
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }),

  new Check('claims_id_token_sub_value', 'requested subject could not be obtained', async (ctx) => {
    const { oidc } = ctx;

    if (!oidc.claims.id_token || !oidc.claims.id_token.sub || !('value' in oidc.claims.id_token.sub)) {
      return Check.NO_NEED_TO_PROMPT;
    }

    let sub = oidc.session.accountId;
    if (sub === undefined) {
      return Check.REQUEST_PROMPT;
    }

    if (oidc.client.subjectType === 'pairwise') {
      sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(ctx, sub, oidc.client);
    }

    if (oidc.claims.id_token.sub.value !== sub) {
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }, ({ oidc }) => ({ sub: oidc.claims.id_token.sub })),

  new Check('essential_acrs', 'none of the requested ACRs could not be obtained', (ctx) => {
    const { oidc } = ctx;
    const request = get(oidc.claims, 'id_token.acr', {});

    if (!request || !request.essential || !request.values) {
      return Check.NO_NEED_TO_PROMPT;
    }

    if (!Array.isArray(oidc.claims.id_token.acr.values)) {
      throw new errors.InvalidRequest('invalid claims.id_token.acr.values type');
    }

    if (request.values.includes(oidc.acr)) {
      return Check.NO_NEED_TO_PROMPT;
    }

    return Check.REQUEST_PROMPT;
  }, ({ oidc }) => ({ acr: oidc.claims.id_token.acr })),

  new Check('essential_acr', 'requested ACR could not be obtained', (ctx) => {
    const { oidc } = ctx;
    const request = get(oidc.claims, 'id_token.acr', {});

    if (!request || !request.essential || !request.value) {
      return Check.NO_NEED_TO_PROMPT;
    }

    if (request.value === oidc.acr) {
      return Check.NO_NEED_TO_PROMPT;
    }

    return Check.REQUEST_PROMPT;
  }, ({ oidc }) => ({ acr: oidc.claims.id_token.acr })),
)

/* CONSENT PROMPT */
new Prompt(
  { name: 'consent', requestable: true },

  new Check('native_client_prompt', 'native clients require End-User interaction', 'interaction_required', (ctx) => {
    const { oidc } = ctx;
    if (
      oidc.client.applicationType === 'native'
      && oidc.params.response_type !== 'none'
      && (!oidc.result || !('consent' in oidc.result))
    ) {
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }),

  new Check('op_scopes_missing', 'requested scopes not granted', (ctx) => {
    const { oidc } = ctx;
    const encounteredScopes = new Set(oidc.grant.getOIDCScopeEncountered().split(' '));

    let missing;
    for (const scope of oidc.requestParamOIDCScopes) { // eslint-disable-line no-restricted-syntax
      if (!encounteredScopes.has(scope)) {
        missing || (missing = []);
        missing.push(scope);
      }
    }

    if (missing && missing.length) {
      ctx.oidc[missingOIDCScope] = missing;
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }, ({ oidc }) => ({ missingOIDCScope: oidc[missingOIDCScope] })),

  new Check('op_claims_missing', 'requested claims not granted', (ctx) => {
    const { oidc } = ctx;
    const encounteredClaims = new Set(oidc.grant.getOIDCClaimsEncountered());

    let missing;
    for (const claim of oidc.requestParamClaims) { // eslint-disable-line no-restricted-syntax
      if (!encounteredClaims.has(claim) && !['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim)) {
        missing || (missing = []);
        missing.push(claim);
      }
    }

    if (missing && missing.length) {
      ctx.oidc[missingOIDCClaims] = missing;
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }, ({ oidc }) => ({ missingOIDCClaims: oidc[missingOIDCClaims] })),

  // checks resource server scopes
  new Check('rs_scopes_missing', 'requested scopes not granted', (ctx) => {
    const { oidc } = ctx;

    let missing;

    // eslint-disable-next-line no-restricted-syntax
    for (const [indicator, resourceServer] of Object.entries(ctx.oidc.resourceServers)) {
      const encounteredScopes = new Set(oidc.grant.getResourceScopeEncountered(indicator).split(' '));
      const requestedScopes = ctx.oidc.requestParamScopes;
      const availableScopes = resourceServer.scopes;

      for (const scope of requestedScopes) { // eslint-disable-line no-restricted-syntax
        if (availableScopes.has(scope) && !encounteredScopes.has(scope)) {
          missing || (missing = {});
          missing[indicator] || (missing[indicator] = []);
          missing[indicator].push(scope);
        }
      }
    }

    if (missing && Object.keys(missing).length) {
      ctx.oidc[missingResourceScopes] = missing;
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }, ({ oidc }) => ({ missingResourceScopes: oidc[missingResourceScopes] })),
)
]
```
<a id="interactions-policy-default-interaction-policy-description"></a><details><summary>(Click to expand) default interaction policy description</summary><br>


The default interaction policy consists of two available prompts, login and consent <br/><br/>
 - `login` does the following checks:
 - no_session - checks that there's an established session, an authenticated end-user
 - max_age - processes the max_age parameter (when the session's auth_time is too old it requires login)
 - id_token_hint - processes the id_token_hint parameter (when the end-user sub differs it requires login)
 - claims_id_token_sub_value - processes the claims parameter `sub` (when the `claims` parameter requested sub differs it requires login)
 - essential_acrs - processes the claims parameter `acr` (when the current acr is not amongst the `claims` parameter essential `acr.values` it requires login)
 - essential_acr - processes the claims parameter `acr` (when the current acr is not equal to the `claims` parameter essential `acr.value` it requires login) <br/><br/>
 - `consent` does the following checks:
 - native_client_prompt - native clients always require re-consent
 - op_scopes_missing - requires consent when the requested scope includes scope values previously not requested
 - op_claims_missing - requires consent when the requested claims parameter includes claims previously not requested
 - rs_scopes_missing - requires consent when the requested resource indicated scope values include scopes previously not requested <br/><br/> These checks are the best practice for various privacy and security reasons.  


</details>
<a id="interactions-policy-disabling-default-consent-checks"></a><details><summary>(Click to expand) disabling default consent checks</summary><br>


You may be required to skip (silently accept) some of the consent checks, while it is discouraged there are valid reasons to do that, for instance in some first-party scenarios or going with pre-existing, previously granted, consents. To simply silenty "accept" first-party/resource indicated scopes or pre-agreed upon claims use the `loadExistingGrant` configuration helper function, in there you may just instantiate (and save!) a grant for the current clientId and accountId values.  


</details>
<a id="interactions-policy-modifying-the-default-interaction-policy"></a><details><summary>(Click to expand) modifying the default interaction policy
</summary><br>

```js
const { interactionPolicy: { Prompt, Check, base } } = require('oidc-provider');
const basePolicy = base()
// basePolicy.get(name) => returns a Prompt instance by its name
// basePolicy.remove(name) => removes a Prompt instance by its name
// basePolicy.add(prompt, index) => adds a Prompt instance to a specific index, default is add the prompt as the last one
// prompt.checks.get(reason) => returns a Check instance by its reason
// prompt.checks.remove(reason) => removes a Check instance by its reason
// prompt.checks.add(check, index) => adds a Check instance to a specific index, default is add the check as the last one
```
</details>

### interactions.url

Function used to determine where to redirect User-Agent for necessary interaction, can return both absolute and relative urls.  


_**default value**_:
```js
async function interactionsUrl(ctx, interaction) {
  return `/interaction/${interaction.uid}`;
}
```

### issueRefreshToken

Function used to decide whether a refresh token will be issued or not   
  


_**default value**_:
```js
async function issueRefreshToken(ctx, client, code) {
  return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
}
```
<a id="issue-refresh-token-to-always-issue-a-refresh-tokens"></a><details><summary>(Click to expand) To always issue a refresh tokens ...</summary><br>


... If a client has the grant allowed and scope includes offline_access or the client is a public web client doing code flow. Configure `issueRefreshToken` like so
  

```js
async issueRefreshToken(ctx, client, code) {
  if (!client.grantTypeAllowed('refresh_token')) {
    return false;
  }
  return code.scopes.has('offline_access') || (client.applicationType === 'web' && client.tokenEndpointAuthMethod === 'none');
}
```
</details>

### loadExistingGrant

Helper function used to load existing but also just in time pre-established Grants to attempt to resolve an Authorization Request with. Default: loads a grant based on the interaction result `consent.grantId` first, falls back to the existing grantId for the client in the current session.  


_**default value**_:
```js
async function loadExistingGrant(ctx) {
  const grantId = (ctx.oidc.result
    && ctx.oidc.result.consent
    && ctx.oidc.result.consent.grantId) || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);
  if (grantId) {
    return ctx.oidc.provider.Grant.find(grantId);
  }
  return undefined;
}
```

### pairwiseIdentifier

Function used by the OP when resolving pairwise ID Token and Userinfo sub claim values. See [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)  

_**recommendation**_: Since this might be called several times in one request with the same arguments consider using memoization or otherwise caching the result based on account and client ids.  


_**default value**_:
```js
async function pairwiseIdentifier(ctx, accountId, client) {
  return crypto.createHash('sha256')
    .update(client.sectorIdentifier)
    .update(accountId)
    .update(os.hostname()) // put your own unique salt here, or implement other mechanism
    .digest('hex');
}
```

### pkce

[RFC7636 - Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636.html)  

PKCE configuration such as available methods and policy check on required use of PKCE  


### pkce.methods

Fine-tune the supported code challenge methods. Supported values are
 - `S256`
 - `plain`  


_**default value**_:
```js
[
  'S256'
]
```

### pkce.required

Configures if and when the OP requires clients to use PKCE. This helper is called whenever an authorization request lacks the code_challenge parameter. Return
 - `false` to allow the request to continue without PKCE
 - `true` to abort the request  


_**default value**_:
```js
function pkceRequired(ctx, client) {
  return true;
}
```

### renderError

Function used to present errors to the User-Agent  


_**default value**_:
```js
async function renderError(ctx, out, error) {
  ctx.type = 'html';
  ctx.body = `<!DOCTYPE html>
    <head>
      <title>oops! something went wrong</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>oops! something went wrong</h1>
        ${Object.entries(out).map(([key, value]) => `<pre><strong>${key}</strong>: ${htmlSafe(value)}</pre>`).join('')}
      </div>
    </body>
    </html>`;
}
```

### responseTypes

Array of response_type values that the OP supports. The default omits all response types that result in access tokens being issued by the authorization endpoint directly as per [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.1.2) You can still enable them if you need to.   
  


_**default value**_:
```js
[
  'code id_token',
  'code',
  'id_token',
  'none'
]
```
<a id="response-types-supported-values-list"></a><details><summary>(Click to expand) Supported values list</summary><br>


These are values defined in [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#Authentication) and [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
  

```js
[
  'code',
  'id_token', 'id_token token',
  'code id_token', 'code token', 'code id_token token',
  'none',
]
```
</details>

### revokeGrantPolicy

Function called in a number of different context to determine whether an underlying Grant entry should also be revoked or not.   
 contexts:
 - RP-Initiated Logout
 - Refresh Token Revocation
 - Authorization Code re-use
 - Device Code re-use
 - Backchannel Authentication Request re-use
 - Rotated Refresh Token re-use  


_**default value**_:
```js
function revokeGrantPolicy(ctx) {
  return true;
}
```

### rotateRefreshToken

Configures if and how the OP rotates refresh tokens after they are used. Supported values are
 - `false` refresh tokens are not rotated and their initial expiration date is final
 - `true` refresh tokens are rotated when used, current token is marked as consumed and new one is issued with new TTL, when a consumed refresh token is encountered an error is returned instead and the whole token chain (grant) is revoked
 - `function` returning true/false, true when rotation should occur, false when it shouldn't   
 <br/><br/>   
 The default configuration value puts forth a sensible refresh token rotation policy
 - only allows refresh tokens to be rotated (have their TTL prolonged by issuing a new one) for one year
 - otherwise always rotate public client tokens that are not sender-constrained
 - otherwise only rotate tokens if they're being used close to their expiration (>= 70% TTL passed)  


_**default value**_:
```js
function rotateRefreshToken(ctx) {
  const { RefreshToken: refreshToken, Client: client } = ctx.oidc.entities;
  // cap the maximum amount of time a refresh token can be
  // rotated for up to 1 year, afterwards its TTL is final
  if (refreshToken.totalLifetime() >= 365.25 * 24 * 60 * 60) {
    return false;
  }
  // rotate non sender-constrained public client refresh tokens
  if (client.tokenEndpointAuthMethod === 'none' && !refreshToken.isSenderConstrained()) {
    return true;
  }
  // rotate if the token is nearing expiration (it's beyond 70% of its lifetime)
  return refreshToken.ttlPercentagePassed() >= 70;
}
```

### routes

Routing values used by the OP. Only provide routes starting with "/"  


_**default value**_:
```js
{
  authorization: '/auth',
  backchannel_authentication: '/backchannel',
  code_verification: '/device',
  device_authorization: '/device/auth',
  end_session: '/session/end',
  introspection: '/token/introspection',
  jwks: '/jwks',
  pushed_authorization_request: '/request',
  registration: '/reg',
  revocation: '/token/revocation',
  token: '/token',
  userinfo: '/me'
}
```

### scopes

Array of additional scope values that the OP signals to support in the discovery endpoint. Only add scopes the OP has a corresponding resource for. Resource Server scopes don't belong here, see `features.resourceIndicators` for configuring those.  


_**default value**_:
```js
[
  'openid',
  'offline_access'
]
```

### sectorIdentifierUriValidate

Function called to make a decision about whether sectorIdentifierUri of a client being loaded, registered, or updated should be fetched and its contents validated against the client metadata.  


_**default value**_:
```js
function sectorIdentifierUriValidate(client) {
  // @param client - the Client instance
  return true;
}
```

### subjectTypes

Array of the Subject Identifier types that this OP supports. When only `pairwise` is supported it becomes the default `subject_type` client metadata value. Valid types are
 - `public`
 - `pairwise`  


_**default value**_:
```js
[
  'public'
]
```

### tokenEndpointAuthMethods

Array of Client Authentication methods supported by this OP's Token Endpoint  


_**default value**_:
```js
[
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt',
  'none'
]
```
<a id="token-endpoint-auth-methods-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'none',
  'client_secret_basic', 'client_secret_post',
  'client_secret_jwt', 'private_key_jwt',
  'tls_client_auth', 'self_signed_tls_client_auth', // these methods are only available when features.mTLS is configured
]
```
</details>

### ttl

description: Expirations for various token and session types. The value can be a number (in seconds) or a synchronous function that dynamically returns value based on the context.   
  

_**recommendation**_: Do not set token TTLs longer then they absolutely have to be, the shorter the TTL, the better.  

_**recommendation**_: Rather than setting crazy high Refresh Token TTL look into `rotateRefreshToken` configuration option which is set up in way that when refresh tokens are regularly used they will have their TTL refreshed (via rotation). This is inline with the [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13)  


_**default value**_:
```js
{
  AccessToken: function AccessTokenTTL(ctx, token, client) {
    if (token.resourceServer) {
      return token.resourceServer.accessTokenTTL || 60 * 60; // 1 hour in seconds
    }
    return 60 * 60; // 1 hour in seconds
  },
  AuthorizationCode: 600 /* 10 minutes in seconds */,
  BackchannelAuthenticationRequest: function BackchannelAuthenticationRequestTTL(ctx, request, client) {
    if (ctx && ctx.oidc && ctx.oidc.params.requested_expiry) {
      return Math.min(10 * 60, +ctx.oidc.params.requested_expiry); // 10 minutes in seconds or requested_expiry, whichever is shorter
    }
  
    return 10 * 60; // 10 minutes in seconds
  },
  ClientCredentials: function ClientCredentialsTTL(ctx, token, client) {
    if (token.resourceServer) {
      return token.resourceServer.accessTokenTTL || 10 * 60; // 10 minutes in seconds
    }
    return 10 * 60; // 10 minutes in seconds
  },
  DeviceCode: 600 /* 10 minutes in seconds */,
  Grant: 1209600 /* 14 days in seconds */,
  IdToken: 3600 /* 1 hour in seconds */,
  Interaction: 3600 /* 1 hour in seconds */,
  RefreshToken: function RefreshTokenTTL(ctx, token, client) {
    if (
      ctx && ctx.oidc.entities.RotatedRefreshToken
      && client.applicationType === 'web'
      && client.tokenEndpointAuthMethod === 'none'
      && !token.isSenderConstrained()
    ) {
      // Non-Sender Constrained SPA RefreshTokens do not have infinite expiration through rotation
      return ctx.oidc.entities.RotatedRefreshToken.remainingTTL;
    }
  
    return 14 * 24 * 60 * 60; // 14 days in seconds
  },
  Session: 1209600 /* 14 days in seconds */
}
```
<a id="ttl-to-resolve-a-ttl-on-runtime-for-each-new-token"></a><details><summary>(Click to expand) To resolve a ttl on runtime for each new token</summary><br>


Configure `ttl` for a given token type with a function like so, this must return a value, not a Promise.
  

```js
{
  ttl: {
    AccessToken(ctx, token, client) {
      // return a Number (in seconds) for the given token (first argument), the associated client is
      // passed as a second argument
      // Tip: if the values are entirely client based memoize the results
      return resolveTTLfor(token, client);
    },
  },
}
```
</details>

### enabledJWA

Fine-tune the algorithms your provider will support by declaring algorithm values for each respective JWA use  

_**recommendation**_: Only allow JWA algs that are necessary. The current defaults are based on recommendations from the [JWA specification](https://www.rfc-editor.org/rfc/rfc7518.html) + enables RSASSA-PSS based on current guidance in FAPI. "none" JWT algs are disabled by default but available if you need them.  


### enabledJWA.authorizationEncryptionAlgValues

JWE "alg" Algorithm values the provider supports for JWT Authorization response (JARM) encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'dir'
]
```
<a id="enabled-jwa-authorization-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
  // direct encryption
  'dir',
]
```
</details>

### enabledJWA.authorizationEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the provider supports to encrypt JWT Authorization Responses (JARM) with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-authorization-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### enabledJWA.authorizationSigningAlgValues

JWS "alg" Algorithm values the provider supports to sign JWT Authorization Responses (JARM) with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="enabled-jwa-authorization-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>

### enabledJWA.dPoPSigningAlgValues

JWS "alg" Algorithm values the provider supports to verify signed DPoP Proof JWTs with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="enabled-jwa-d-po-p-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
]
```
</details>

### enabledJWA.idTokenEncryptionAlgValues

JWE "alg" Algorithm values the provider supports for ID Token encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'dir'
]
```
<a id="enabled-jwa-id-token-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
  // direct encryption
  'dir',
]
```
</details>

### enabledJWA.idTokenEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the provider supports to encrypt ID Tokens with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-id-token-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### enabledJWA.idTokenSigningAlgValues

JWS "alg" Algorithm values the provider supports to sign ID Tokens with.   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="enabled-jwa-id-token-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
  'HS256', 'HS384', 'HS512',
  'none',
]
```
</details>

### enabledJWA.introspectionEncryptionAlgValues

JWE "alg" Algorithm values the provider supports for JWT Introspection response encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'dir'
]
```
<a id="enabled-jwa-introspection-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
  // direct encryption
  'dir',
]
```
</details>

### enabledJWA.introspectionEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the provider supports to encrypt JWT Introspection responses with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-introspection-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### enabledJWA.introspectionSigningAlgValues

JWS "alg" Algorithm values the provider supports to sign JWT Introspection responses with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="enabled-jwa-introspection-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
  'HS256', 'HS384', 'HS512',
  'none',
]
```
</details>

### enabledJWA.requestObjectEncryptionAlgValues

JWE "alg" Algorithm values the provider supports to receive encrypted Request Objects (JAR) with   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'dir'
]
```
<a id="enabled-jwa-request-object-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
  // direct encryption
  'dir',
]
```
</details>

### enabledJWA.requestObjectEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the provider supports to decrypt Request Objects (JAR) with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-request-object-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### enabledJWA.requestObjectSigningAlgValues

JWS "alg" Algorithm values the provider supports to receive signed Request Objects (JAR) with   
  


_**default value**_:
```js
[
  'HS256',
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="enabled-jwa-request-object-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
  'HS256', 'HS384', 'HS512',
  'none',
]
```
</details>

### enabledJWA.tokenEndpointAuthSigningAlgValues

JWS "alg" Algorithm values the provider supports for signed JWT Client Authentication   
  


_**default value**_:
```js
[
  'HS256',
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="enabled-jwa-token-endpoint-auth-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>

### enabledJWA.userinfoEncryptionAlgValues

JWE "alg" Algorithm values the provider supports for UserInfo Response encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'dir'
]
```
<a id="enabled-jwa-userinfo-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
  // direct encryption
  'dir',
]
```
</details>

### enabledJWA.userinfoEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the provider supports to encrypt UserInfo responses with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-userinfo-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### enabledJWA.userinfoSigningAlgValues

JWS "alg" Algorithm values the provider supports to sign UserInfo responses with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="enabled-jwa-userinfo-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
  'HS256', 'HS384', 'HS512',
  'none',
]
```
</details>
<!-- END CONF OPTIONS -->

## FAQ

### ID Token does not include claims other than sub

Only response types that do not end up with an access_token (so, response_type=id_token) have
end-user claims other than `sub` in their ID Tokens. This is the
[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) spec behaviour. Read
it you'll see requesting claims through the scope parameter only adds these claims to userinfo
unless the response_type is `id_token` in which case they're added there. All other response types
have access to the userinfo endpoint which returns these scope-requested claims. The other option is
to allow clients to request specific claims from a source they expect it in via the `claims`
parameter.

But, if you absolutely need to have scope-requested claims in ID Tokens you can use the
[`conformIdTokenClaims`](#conformidtokenclaims) configuration option.

### Why does my .well-known/openid-configuration link to http endpoints instead of https endpoints?

Your provider is behind a TLS terminating proxy, tell your provider instance to trust the proxy
headers. More on this in
[Trusting TLS offloading proxies](#trusting-tls-offloading-proxies)

### My client_secret with special characters is not working

You're likely using client_secret_basic client authentication and the oidc-provider is actually
exhibiting conform behaviour. It's likely a bug in your client software - it's not encoding the
header correctly.

`client_secret_basic` is not 100% basic http auth, the username and password tokens are supposed to
be additionally formencoded.

A proper way of submitting `client_id` and `client_secret` using `client_secret_basic` is
`Authorization: base64(formEncode(client_id):formEncode(client_secret))` as per
https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1 incl.
https://www.rfc-editor.org/rfc/rfc6749.html#appendix-B

Example:

```js
const client_id = 'an:identifier';
const client_secret = 'some secure & non-standard secret';

// After formencoding these two tokens
const encoded_id = 'an%3Aidentifier';
const encoded_secret = 'some+secure+%26+non-standard+secret';

// Basic auth header format Authorization: Basic base64(encoded_id + ':' + encoded_secret)
// Authorization: Basic YW4lM0FpZGVudGlmaWVyOnNvbWUrc2VjdXJlKyUyNitub24tc3RhbmRhcmQrc2VjcmV0
```

So essentially, your client is not submitting the client auth in a conform way and you should fix
that.

### I'm getting a client authentication failed error with no details

Every client is configured with one of 7 available
[`token_endpoint_auth_method` values](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method)
and it must adhere to how that given method must be submitted. Submitting multiple means of
authentication is also not possible. If you're a provider operator you're encouraged to set up
listeners for errors
(see [events.md](https://github.com/panva/node-oidc-provider/blob/v7.x/docs/events.md)) and
deliver them to client developers out-of-band, e.g. by logs in an admin interface.

```js
function handleClientAuthErrors({ headers: { authorization }, oidc: { body, client } }, err) {
  if (err.statusCode === 401 && err.message === 'invalid_client') {
    // console.log(err);
    // save error details out-of-bands for the client developers, `authorization`, `body`, `client`
    // are just some details available, you can dig in ctx object for more.
  }
}
provider.on('grant.error', handleClientAuthErrors);
provider.on('introspection.error', handleClientAuthErrors);
provider.on('revocation.error', handleClientAuthErrors);
```

### Refresh Tokens

  > I'm not getting refresh_token from token_endpoint grant_type=authorization_code responses, why?  

Do you support offline_access scope and consent prompt? Did the client request them in the
authentication request?

  > Yeah, still no refresh_token  

Does the client have grant_type=refresh_token configured?

  > Aaaah, that was it. (or one of the above if you follow [Core 1.0#OfflineAccess](http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess))  

***

  > The Authorization Server MAY grant Refresh Tokens in other contexts that are beyond the scope of this specification. How about that?

Yeah, yeah, see [configuration](#issuerefreshtoken)

### Password Grant Type, ROPC

If you need it today something's wrong!

- https://www.youtube.com/watch?v=qMtYaDmhnHU
- https://www.youtube.com/watch?v=zuVuhl_Axbs

ROPC falls beyond the scope of what the library can do magically on it's own having only accountId
and the claims, it does not ask for an interface necessary to find an account by a username nor by
validating the password digest. Custom implementation using the provided
[`registerGrantType`](#custom-grant-types) API is simple enough if you absolutely need ROPC.

### How to display, on the website of the OP itself, if the user is signed-in or not

```js
const ctx = provider.app.createContext(req, res)
const session = await provider.Session.get(ctx)
const signedIn = !!session.accountId
```

### Client Credentials only clients

You're getting the `redirect_uris is mandatory property` error but Client Credential clients
don't need `redirect_uris` or `response_types`... You're getting this error
because they are required properties, but they can be empty...

```js
{
  // ... rest of the client configuration
  redirect_uris: [],
  response_types: [],
  grant_types: ['client_credentials']
}
```

### Resource Server only clients (e.g. for token introspection)

You're getting the `redirect_uris is mandatory property` error but the resource server needs
none. You're getting this error because they are required properties, but they can be empty...

```js
{
  // ... rest of the client configuration
  redirect_uris: [],
  response_types: [],
  grant_types: []
}
```


[support-sponsor]: https://github.com/sponsors/panva
