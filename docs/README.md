# oidc-provider API documentation

oidc-provider allows to be extended and configured in various ways to fit a variety of use cases. You
will have to configure your instance with how to find your user accounts, where to store and retrieve
persisted data from and where your end-user interactions happen. The [example](/example) application
is a good starting point to get an idea of what you should provide.

## Sponsor

[<img width="65" height="65" align="left" src="https://avatars.githubusercontent.com/u/2824157?s=75&v=4" alt="auth0-logo">][sponsor-auth0] If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan at [auth0.com/developers][sponsor-auth0].<br><br>

## Support

If you or your business use oidc-provider, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

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
  features: {
    introspection: { enabled: true },
    revocation: { enabled: true },
  },
  formats: {
    AccessToken: 'jwt',
  },
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
oidc.callback

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
doing so it will save a short-lived session and dump its identifier into a cookie scoped to the
resolved interaction path.

This session contains:

- details of the interaction that is required
- all authorization request parameters
- current session account ID should there be one
- the uid of the authorization request
- the url to redirect the user to once interaction is finished

oidc-provider expects that you resolve the prompt interaction and then redirect the User-Agent back
with the results.

Once the required interactions are finished you are expected to redirect back to the authorization
endpoint, affixed by the uid of the original request and the interaction results stored in the
interaction session object.

The Provider instance comes with helpers that aid with getting interaction details as well as
packing the results. See them used in the [step-by-step](https://github.com/panva/node-oidc-provider-example)
or [in-repo](/example) examples.


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
    account: '7ff1d19a-d3fd-4863-978e-8cce75fa880c', // logged-in account id
    acr: string, // acr value for the authentication
    remember: boolean, // true if provider should use a persistent cookie rather than a session one, defaults to true
    ts: number, // unix timestamp of the authentication, defaults to now()
  },

  // consent was given by the user to the client for this session
  consent: {
    rejectedScopes: [], // array of strings, scope names the end-user has not granted
    rejectedClaims: [], // array of strings, claim names the end-user has not granted
  },

  // meta is a free object you may store alongside an authorization. It can be useful
  // during the interaction check to verify information on the ongoing session.
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

**`#provider.interactionResult`**
Unlike `#provider.interactionFinished` authorization request resume uri is returned instead of
immediate http redirect. It should be used when custom response handling is needed e.g. making AJAX
login where redirect information is expected to be available in the response.

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
  meta: { // [optional] object with keys being client_ids present in clients with their respective meta
    [client_id]: {},
  }
} = {})
```

```js
// with express
expressApp.post('/interaction/:uid/login', async (req, res) => {
  await provider.setProviderSession(req, res, { account: 'accountId' });
  // ...
});

// with koa
router.post('/interaction/:uid/login', async (ctx, next) => {
  await provider.setProviderSession(ctx.req, ctx.res, { account: 'accountId' });
  // ...
});
```


## Custom Grant Types
oidc-provider comes with the basic grants implemented, but you can register your own grant types,
for example to implement an [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/rfc8693). You can
check the standard grant factories [here](/lib/actions/grants).

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
   * `check_session_origin`
   * `check_session`
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
connectApp.use('/oidc', oidc.callback);
```

### to a `fastify` application
```js
// assumes fastify ^3.0.0
await app.register(require('fastify-express'));
// or
// await app.register(require('middie'));

fastifyApp.use('/oidc', oidc.callback);
```

### to a `hapi` application
```js
// assumes @hapi/hapi ^20.0.0
const { callback } = oidc;
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
const { callback } = oidc;
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
expressApp.use('/oidc', oidc.callback);
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

- [adapter ❗](#adapter)
- [clients ❗](#clients)
- [findAccount ❗](#findaccount)
- [jwks ❗](#jwks)
- [features ❗](#features)
  - [backchannelLogout](#featuresbackchannellogout)
  - [claimsParameter](#featuresclaimsparameter)
  - [clientCredentials](#featuresclientcredentials)
  - [deviceFlow](#featuresdeviceflow)
  - [devInteractions](#featuresdevinteractions)
  - [dPoP](#featuresdpop)
  - [encryption](#featuresencryption)
  - [fapiRW](#featuresfapirw)
  - [frontchannelLogout](#featuresfrontchannellogout)
  - [ietfJWTAccessTokenProfile](#featuresietfjwtaccesstokenprofile)
  - [introspection](#featuresintrospection)
  - [jwtIntrospection](#featuresjwtintrospection)
  - [jwtResponseModes](#featuresjwtresponsemodes)
  - [jwtUserinfo](#featuresjwtuserinfo)
  - [mTLS](#featuresmtls)
  - [pushedAuthorizationRequests](#featurespushedauthorizationrequests)
  - [registration](#featuresregistration)
  - [registrationManagement](#featuresregistrationmanagement)
  - [requestObjects](#featuresrequestobjects)
  - [resourceIndicators](#featuresresourceindicators)
  - [revocation](#featuresrevocation)
  - [sessionManagement](#featuressessionmanagement)
  - [userinfo](#featuresuserinfo)
  - [webMessageResponseMode](#featureswebmessageresponsemode)
- [acrValues](#acrvalues)
- [audiences](#audiences)
- [claims ❗](#claims)
- [clientBasedCORS](#clientbasedcors)
- [clientDefaults](#clientdefaults)
- [clockTolerance](#clocktolerance)
- [conformIdTokenClaims ❗](#conformidtokenclaims)
- [cookies](#cookies)
- [discovery](#discovery)
- [dynamicScopes](#dynamicscopes)
- [expiresWithSession](#expireswithsession)
- [extraAccessTokenClaims](#extraaccesstokenclaims)
- [extraClientMetadata](#extraclientmetadata)
- [extraParams](#extraparams)
- [formats](#formats)
- [httpOptions](#httpoptions)
- [interactions ❗](#interactions)
- [issueRefreshToken](#issuerefreshtoken)
- [pairwiseIdentifier](#pairwiseidentifier)
- [pkce](#pkce)
- [renderError](#rendererror)
- [responseTypes](#responsetypes)
- [rotateRefreshToken](#rotaterefreshtoken)
- [routes](#routes)
- [scopes](#scopes)
- [subjectTypes](#subjecttypes)
- [tokenEndpointAuthMethods](#tokenendpointauthmethods)
- [ttl ❗](#ttl)
- [whitelistedJWA](#whitelistedjwa)

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


application_type, client_id, client_name, client_secret, client_uri, contacts, default_acr_values, default_max_age, grant_types, id_token_signed_response_alg, initiate_login_uri, jwks, jwks_uri, logo_uri, policy_uri, post_logout_redirect_uris, redirect_uris, require_auth_time, response_types, scope, sector_identifier_uri, subject_type, token_endpoint_auth_method, tos_uri, userinfo_signed_response_alg <br/><br/>The following metadata is available but may not be recognized depending on your provider's configuration.<br/><br/> authorization_encrypted_response_alg, authorization_encrypted_response_enc, authorization_signed_response_alg, backchannel_logout_session_required, backchannel_logout_uri, frontchannel_logout_session_required, frontchannel_logout_uri, id_token_encrypted_response_alg, id_token_encrypted_response_enc, introspection_encrypted_response_alg, introspection_encrypted_response_enc, introspection_endpoint_auth_method, introspection_endpoint_auth_signing_alg, introspection_signed_response_alg, request_object_encryption_alg, request_object_encryption_enc, request_object_signing_alg, request_uris, revocation_endpoint_auth_method, revocation_endpoint_auth_signing_alg, tls_client_auth_san_dns, tls_client_auth_san_email, tls_client_auth_san_ip, tls_client_auth_san_uri, tls_client_auth_subject_dn, tls_client_certificate_bound_access_tokens, token_endpoint_auth_signing_alg, userinfo_encrypted_response_alg, userinfo_encrypted_response_enc, web_message_uris  


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

JSON Web Key Set used by the provider for signing and encryption. The object must be in [JWK Set format](https://tools.ietf.org/html/rfc7517#section-5). All provided keys must be private keys. **Note:** Be sure to follow best practices for distributing private keying material and secrets for your respective target deployment environment.   
   
 Supported key types are:   
 - RSA
 - OKP (Ed25519, Ed448, X25519, X448 sub types)
 - EC (P-256, secp256k1, P-384, and P-521 curves)   
  

_**recommendation**_: **Provider key rotation** - The following action order is recommended when rotating signing keys on a distributed deployment with rolling reloads in place.
 1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become available for verification should they be encountered but not yet used for signing
 2. reload all your processes
 3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be used for signing after reload
 4. reload all your processes  

<a id="jwks-generating-keys"></a><details><summary>(Click to expand) Generating keys
</summary><br>

```js
// npm install jose@2
const { JWKS: { KeyStore } } = require('jose');
const keystore = new KeyStore();
keystore.generateSync('RSA', 2048, { alg: 'RS256', use: 'sig' });
console.log('this is the full private JWKS:\n', keystore.toJWKS(true));
```
</details>
<a id="jwks-generating-keys-for-both-signing-and-encryption"></a><details><summary>(Click to expand) Generating keys for both signing and encryption</summary><br>


Re-using the same keys for both encryption and signing is discouraged so it is best to generate one with `{ use: 'sig' }` and another with `{ use: 'enc' }`, e.g.
  

```js
// npm install jose@2
const { JWKS: { KeyStore } } = require('jose');
const keystore = new KeyStore();
Promise.all([
  keystore.generate('RSA', 2048, { use: 'sig' }),
  keystore.generate('RSA', 2048, { use: 'enc' }),
  keystore.generate('EC', 'P-256', { use: 'sig' }),
  keystore.generate('EC', 'P-256', { use: 'enc' }),
  keystore.generate('OKP', 'Ed25519', { use: 'sig' }),
]).then(function () {
  console.log('this is the full private JWKS:\n', keystore.toJWKS(true));
});
```
</details>

### features

Enable/disable features. Some features are still either based on draft or experimental RFCs. Enabling those will produce a warning in your console and you must be aware that breaking changes may occur between draft implementations and that those will be published as minor versions of oidc-provider. See the example below on how to acknowledge the specification is a draft (this will remove the warning log) and ensure the provider instance will fail to instantiate if a new version of oidc-provider bundles newer version of the RFC with breaking changes in it.   
  

<a id="features-acknowledging-a-draft-experimental-feature"></a><details><summary>(Click to expand) Acknowledging a draft / experimental feature
</summary><br>

```js
new Provider('http://localhost:3000', {
  features: {
    webMessageResponseMode: {
      enabled: true,
    },
  },
});
// The above code produces this NOTICE
// NOTICE: The following draft features are enabled and their implemented version not acknowledged
// NOTICE:   - OAuth 2.0 Web Message Response Mode - draft 00 (This is an Individual draft. URL: https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00)
// NOTICE: Breaking changes between draft version updates may occur and these will be published as MINOR semver oidc-provider updates.
// NOTICE: You may disable this notice and these potentially breaking updates by acknowledging the current draft version. See https://github.com/panva/node-oidc-provider/tree/v6.6.2/docs/README.md#features
new Provider('http://localhost:3000', {
  features: {
    webMessageResponseMode: {
      enabled: true,
      ack: 0, // < we're acknowledging draft 00 of the RFC
    },
  },
});
// No more NOTICE, at this point if the draft implementation changed to 01 and contained no breaking
// changes, you're good to go, still no NOTICE, your code is safe to run.
// Now lets assume you upgrade oidc-provider version and it bundles draft 02 and it contains breaking
// changes
new Provider('http://localhost:3000', {
  features: {
    webMessageResponseMode: {
      enabled: true,
      ack: 0, // < bundled is 2, but we're still acknowledging 0
    },
  },
});
// Thrown:
// Error: An unacknowledged version of a draft feature is included in this oidc-provider version.
```
</details>

### features.backchannelLogout

[Back-Channel Logout 1.0 - draft 06](https://openid.net/specs/openid-connect-backchannel-1_0-06.html)  

Enables Back-Channel Logout features.   
  


_**default value**_:
```js
{
  enabled: false
}
```

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

[RFC6749](https://tools.ietf.org/html/rfc6749#section-1.3.4) - Client Credentials  

Enables `grant_type=client_credentials` to be used on the token endpoint.  


_**default value**_:
```js
{
  enabled: false
}
```

### features.dPoP

[draft-ietf-oauth-dpop-01](https://tools.ietf.org/html/draft-ietf-oauth-dpop-01) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer  

Enables `DPoP` - mechanism for sender-constraining tokens via a proof-of-possession mechanism on the application level. Browser DPoP Proof generation [here](https://www.npmjs.com/package/dpop).  


_**default value**_:
```js
{
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

[RFC8628](https://tools.ietf.org/html/rfc8628) - OAuth 2.0 Device Authorization Grant  

Enables Device Authorization Grant (Device Flow)  


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

### features.fapiRW

[Financial-grade API - Part 2: Read and Write API Security Profile](https://openid.net/specs/openid-financial-api-part-2-ID2.html)  

Enables extra behaviours defined in FAPI Part 1 & 2 that cannot be achieved by other configuration options, namely:   
 - Request Object `exp` claim is REQUIRED
 - `userinfo_endpoint` becomes a FAPI resource, echoing back the x-fapi-interaction-id header and disabling query string as a mechanism for providing access tokens   
  


_**default value**_:
```js
{
  enabled: false
}
```
<a id="features-fapi-rw-other-configuration-needed-to-reach-fapi-levels"></a><details><summary>(Click to expand) other configuration needed to reach FAPI levels
</summary><br>


- `clientDefaults` for setting different default client `token_endpoint_auth_method`
 - `clientDefaults` for setting different default client `id_token_signed_response_alg`
 - `clientDefaults` for setting different default client `response_types`
 - `clientDefaults` for setting client `tls_client_certificate_bound_access_tokens` to true
 - `features.mTLS` and enable `certificateBoundAccessTokens`
 - `features.mTLS` and enable `selfSignedTlsClientAuth` and/or `tlsClientAuth`
 - `features.claimsParameter`
 - `features.requestObjects` and enable `request` and/or `request_uri`
 - `features.requestObjects.mergingStrategy.name` set to `strict`
 - `whitelistedJWA`
 - (optional) `features.pushedAuthorizationRequests`
 - (optional) `features.jwtResponseModes`  


</details>

### features.frontchannelLogout

[Front-Channel Logout 1.0 - draft 04](https://openid.net/specs/openid-connect-frontchannel-1_0-04.html)  

Enables Front-Channel Logout features   
 Note: Browsers blocking access to cookies from a third party context hinder the reliability of this standard.  


_**default value**_:
```js
{
  enabled: false,
  logoutPendingSource: [AsyncFunction: logoutPendingSource] // see expanded details below
}
```

<details><summary>(Click to expand) features.frontchannelLogout options details</summary><br>


#### logoutPendingSource

HTML source rendered when there are pending front-channel logout iframes to be called to trigger RP logouts. It should handle waiting for the frames to be loaded as well as have a timeout mechanism in it.  


_**default value**_:
```js
async function logoutPendingSource(ctx, frames, postLogoutRedirectUri) {
  ctx.body = `<!DOCTYPE html>
    <head>
      <title>Logout</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
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
          if (loaded === ${frames.length}) {
            redirect();
          }
        }
        Array.prototype.slice.call(document.querySelectorAll('iframe')).forEach(function (element) {
          element.onload = frameOnLoad;
        });
        setTimeout(redirect, 2500);
      </script>
      <noscript>
        Your browser does not support JavaScript or you've disabled it.<br/>
        <a href="${postLogoutRedirectUri}">Continue</a>
      </noscript>
    </body>
    </html>`;
}
```

</details>

### features.ietfJWTAccessTokenProfile

[draft-ietf-oauth-access-token-jwt-05](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-05) - JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens  

Enables the use of `jwt-ietf` JWT Access Token format   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.introspection

[RFC7662](https://tools.ietf.org/html/rfc7662) - OAuth 2.0 Token Introspection  

Enables Token Introspection features   
  


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

[draft-ietf-oauth-jwt-introspection-response-09](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-09) - JWT Response for OAuth Token Introspection  

Enables JWT responses for Token Introspection features   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.jwtResponseModes

[openid-financial-api-jarm-wd-02](https://openid.net/specs/openid-financial-api-jarm-wd-02.html) - JWT Secured Authorization Response Mode (JARM)  

Enables JWT Secured Authorization Responses   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.jwtUserinfo

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - JWT UserInfo Endpoint Responses  

Enables the userinfo to optionally return signed and/or encrypted JWTs, also enables the relevant client metadata for setting up signing and/or encryption  


_**default value**_:
```js
{
  enabled: true
}
```

### features.mTLS

[RFC 8705](https://tools.ietf.org/html/rfc8705) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens  

Enables specific features from the Mutual TLS specification. The three main features have their own specific setting in this feature's configuration object and you must provide functions for resolving some of the functions which are deployment-specific. Note: **This feature is only supported in node runtime >= 12.0.0**   
  


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

Enables section 2.2. Self-Signed Certificate Mutual TLS client authentication method `self_signed_tls_client_auth` for use in the server's `tokenEndpointAuthMethods`, `introspectionEndpointAuthMethods`, and `revocationEndpointAuthMethods` configuration options.  


_**default value**_:
```js
false
```

#### tlsClientAuth

Enables section 2.1. PKI Mutual TLS client authentication method `tls_client_auth` for use in the server's `tokenEndpointAuthMethods`, `introspectionEndpointAuthMethods`, and `revocationEndpointAuthMethods` configuration options.  


_**default value**_:
```js
false
```

</details>

### features.pushedAuthorizationRequests

[draft-ietf-oauth-par-03](https://tools.ietf.org/html/draft-ietf-oauth-par-03) - OAuth 2.0 Pushed Authorization Requests  

Enables the use of `pushed_authorization_request_endpoint` defined by the Pushed Authorization Requests draft.   
  


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
  policies: undefined,
  secretFactory: [Function: secretFactory] // see expanded details below
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

#### policies

define registration and registration management policies applied to client properties. Policies are sync/async functions that are assigned to an Initial Access Token that run before the regular client property validations are run. Multiple policies may be assigned to an Initial Access Token and by default the same policies will transfer over to the Registration Access Token. A policy may throw / reject and it may modify the properties object.   
  


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
Note: referenced policies must always be present when encountered on a token, an AssertionError will be thrown inside the request context if it is not, resulting in a 500 Server Error. Note: the same policies will be assigned to the Registration Access Token after a successful validation. If you wish to assign different policies to the Registration Access Token
  

```js
// inside your final ran policy
ctx.oidc.entities.RegistrationAccessToken.policies = ['update-policy'];
```
</details>
<a id="policies-using-initial-access-token-policies-for-software-statement-dynamic-client-registration-property"></a><details><summary>(Click to expand) Using Initial Access Token policies for software_statement dynamic client registration property</summary><br>


Support modules:
  

```js
// npm install jose@2
const { JWT: { verify }, JWK } = require('jose');
const {
  errors: { InvalidSoftwareStatement, UnapprovedSoftwareStatement, InvalidClientMetadata },
} = require('oidc-provider');
```
features.registration configuration:
  

```js
{
 enabled: true,
 initialAccessToken: true, // to enable adapter-backed initial access tokens
 policies: {
   'softwareStatement': async function (ctx, metadata) {
     if (!('software_statement' in metadata)) {
       throw new InvalidClientMetadata('software_statement must be provided');
     }
     const softwareStatementKey = JWK.asKey(await loadKeyForThisPolicy());
     const statement = metadata.software_statement;
     let payload;
     try {
       payload = verify(value, softwareStatementKey, {
         algorithms: ['PS256'],
         issuer: 'Software Statement Issuer',
       });
       // additional custom validation function
       if (!approvedStatement(value, payload)) {
         throw new UnapprovedSoftwareStatement('software_statement not approved for use');
       }
       // cherry pick the software_statement values and assign them
       // Note: regular validations will run!
       const { client_name, client_uri } = payload;
       Object.assign(metadata, { client_name, client_uri });
     } catch (err) {
       throw new InvalidSoftwareStatement('could not verify software_statement');
     }
   },
 },
}
```
An Initial Access Token that requires and validates the given software statement is created like so
  

```js
new (provider.InitialAccessToken)({ policies: ['softwareStatement'] }).save().then(console.log);
```
</details>

#### secretFactory

Function used to generate random client secrets during dynamic client registration  


_**default value**_:
```js
function secretFactory(ctx) {
  return base64url.encodeBuffer(crypto.randomBytes(64)); // 512 base64url random bits
}
```

</details>

### features.registrationManagement

[OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)  

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

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject) and [JWT Secured Authorization Request (JAR)](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-26) - Request Object  

Enables the use and validations of the `request` and/or `request_uri` parameters.  


_**default value**_:
```js
{
  mergingStrategy: {
    name: 'lax',
    whitelist: [
      'code_challenge',
      'nonce',
      'state'
    ]
  },
  request: false,
  requestUri: true,
  requireSignedRequestObject: false,
  requireUriRegistration: true
}
```

<details><summary>(Click to expand) features.requestObjects options details</summary><br>


#### mergingStrategy.name

defines the provider's strategy when it comes to using regular OAuth 2.0 parameters that are present. Parameters inside the Request Object are ALWAYS used, this option controls whether to combine those with the regular ones or not.   
 Supported values are:   
 - 'lax' (default) This is the behaviour expected by OIDC Core 1.0 - all parameters that are not present in the Resource Object are used when resolving the authorization request.
 - 'strict' This is the behaviour expected by FAPI or JAR, all parameters outside of the Request Object are ignored.
 - 'whitelist' During this strategy only parameters in the configured whitelist are used. This means that pre-signed Request Objects could be used multiple times while the per-transaction whitelisted parameters can be provided using regular OAuth 2.0 syntax.   
  


_**default value**_:
```js
'lax'
```

#### mergingStrategy.whitelist

This whitelist is only used when the 'mergingStrategy.name' value is 'whitelist'.   
  


_**default value**_:
```js
[
  'code_challenge',
  'nonce',
  'state'
]
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

[draft-ietf-oauth-resource-indicators-08](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08) - Resource Indicators for OAuth 2.0  

Enables the use of `resource` parameter for the authorization and token endpoints. In order for the feature to be any useful you must also use the `audiences` function to validate the resource(s) and transform it to the Access Token audience.   
  


_**default value**_:
```js
{
  allowedPolicy: [AsyncFunction: resourceIndicatorsAllowedPolicy], // see expanded details below
  enabled: false
}
```
<a id="features-resource-indicators-example-use"></a><details><summary>(Click to expand) Example use</summary><br>


This example
 - will transform resources to audience and push them down to the audience of access tokens
 - will take both, the parameter and previously granted resources into consideration
 - assumes resource parameters are validated using `features.resourceIndicators.allowedPolicy`
  

```js
// const { InvalidTarget } = Provider.errors;
// `transform` is mapping the resource values to actual aud values
{
  // ...
  async function audiences(ctx, sub, token, use) {
    if (use === 'access_token') {
      const { oidc: { route, client, params: { resource: resourceParam } } } = ctx;
      let grantedResource;
      if (route === 'token') {
        const { oidc: { params: { grant_type } } } = ctx;
        switch (grant_type) {
          case 'authorization_code':
            grantedResource = ctx.oidc.entities.AuthorizationCode.resource;
            break;
          case 'refresh_token':
            grantedResource = ctx.oidc.entities.RefreshToken.resource;
            break;
          case 'urn:ietf:params:oauth:grant-type:device_code':
            grantedResource = ctx.oidc.entities.DeviceCode.resource;
            break;
          default:
        }
      }
      // => array of validated and transformed string audiences or undefined if no audiences
      //    are to be listed
      return transform(resourceParam, grantedResource);
    }
  },
  formats: {
    AccessToken(ctx, token) {
      return token.aud ? 'jwt' : 'opaque';
    }
  },
  // ...
}
```
</details>

<details><summary>(Click to expand) features.resourceIndicators options details</summary><br>


#### allowedPolicy

Function used to check if a request parameter should be processed, e.g. If it is whitelisted for a given client.   
  

_**recommendation**_: Only allow pre-registered resource values, to pre-register these you shall use the `extraClientMetadata` configuration option to define a custom metadata and use that to implement your policy using this function.  


_**default value**_:
```js
async function resourceIndicatorsAllowedPolicy(ctx, resources, client) {
  return true;
}
```

</details>

### features.revocation

[RFC7009](https://tools.ietf.org/html/rfc7009) - OAuth 2.0 Token Revocation  

Enables Token Revocation   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.rpInitiatedLogout

[RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0-01.html)  

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

HTML source rendered when session management feature renders a confirmation prompt for the User-Agent.  


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

HTML source rendered when session management feature concludes a logout but there was no `post_logout_redirect_uri` provided by the client.  


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

### features.sessionManagement

[Session Management 1.0 - draft 30](https://openid.net/specs/openid-connect-session-1_0-30.html)  

Enables Session Management features.   
 Note: Browsers blocking access to cookies from a third party context hinder the reliability of this standard.  


_**default value**_:
```js
{
  enabled: false,
  keepHeaders: false,
  scriptNonce: [Function: sessionManagementScriptNonce] // see expanded details below
}
```

<details><summary>(Click to expand) features.sessionManagement options details</summary><br>


#### keepHeaders

Enables/Disables removing frame-ancestors from Content-Security-Policy and X-Frame-Options headers.  

_**recommendation**_: Only enable this if you know what you're doing either in a followup middleware or your app server, otherwise you shouldn't have the need to touch this option.  


_**default value**_:
```js
false
```

#### scriptNonce

When using `nonce-{random}` CSP policy use this helper function to resolve a nonce to add to the &lt;script&gt; tags in the `check_session_iframe` html source.  


_**default value**_:
```js
function sessionManagementScriptNonce(ctx) {
  return undefined;
}
```

</details>

### features.userinfo

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - UserInfo Endpoint  

Enables the userinfo endpoint.  


_**default value**_:
```js
{
  enabled: true
}
```

### features.webMessageResponseMode

[draft-sakimura-oauth-wmrm-00](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00) - OAuth 2.0 Web Message Response Mode  

Enables `web_message` response mode.   
 Note: Browsers blocking access to cookies from a third party context hinder the reliability of `response_mode=web_message` "no prompt" mode.   
 Note: Although a general advise to use a `helmet` ([express](https://www.npmjs.com/package/helmet), [koa](https://www.npmjs.com/package/koa-helmet)) it is especially advised for your interaction views routes if Web Message Response Mode is available on your deployment.  


_**default value**_:
```js
{
  enabled: false,
  scriptNonce: [Function: webMessageResponseModeScriptNonce] // see expanded details below
}
```

<details><summary>(Click to expand) features.webMessageResponseMode options details</summary><br>


#### scriptNonce

When using `nonce-{random}` CSP policy use this helper function to resolve a nonce to add to the &lt;script&gt; tag in the rendered web_message response mode html source  


_**default value**_:
```js
function webMessageResponseModeScriptNonce(ctx) {
  return undefined;
}
```

</details>

### acceptQueryParamAccessTokens

Several OAuth 2.0 / OIDC profiles prohibit the use of query strings to carry access tokens. This setting either allows (true) or prohibits (false) that mechanism to be used.   
  


_**default value**_:
```js
true
```

### acrValues

Array of strings, the Authentication Context Class References that OP supports.  


_**default value**_:
```js
[]
```

### audiences

Function used to set an audience to issued Access Tokens. The return value should be either:   
 - falsy (no audience, implicitly the client is the only allowed audience of the token)
 - a single string `aud` value (e.g. Such as the Resource Server indicated by the resource parameter)
 - array of string `aud` values (it is supported but NOT RECOMMENDED, consider it DEPRECATED)   
  


_**default value**_:
```js
async function audiences(ctx, sub, token, use) {
  // @param ctx   - koa request context
  // @param sub   - account identifier (subject)
  // @param token - the token to which these additional audiences will be passed to
  // @param use   - can be one of "access_token" or "client_credentials"
  //   depending on where the specific audience is intended to be allowed
  return undefined;
}
```

### claims

Describes the claims that the OpenID Provider MAY be able to supply values for. It is also used to define which claims fall under what scope (configure `{ ['scope']: ['claim', 'another-claim'] }`) as well as to expose additional claims that are available to RPs via the `claims` authorization parameter (configure as `{ ['claim']: null }`).   
  


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
  return true;
}
```

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

_**recommendation**_: Only set this to a reasonable value when needed to cover server-side client and oidc-provider server clock skew. More than 5 minutes (if needed) is probably a sign something else is wrong.  


_**default value**_:
```js
0
```

### conformIdTokenClaims

ID Token only contains End-User claims when the requested `response_type` is `id_token`  

[Core 1.0 - Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) defines that claims requested using the `scope` parameter are only returned from the UserInfo Endpoint unless the `response_type` is `id_token`. This is the default oidc-provider behaviour, you can turn this behaviour off and return End-User claims with all ID Tokens by providing this configuration as `false`.   
  


_**default value**_:
```js
true
```

### cookies

Options for the [cookie module](https://github.com/pillarjs/cookies#cookiesset-name--value---options--) used to keep track of various User-Agent states.  


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
  maxAge: 1209600000,
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
  session: '_session',
  state: '_state'
}
```

### cookies.short

Options for short-term cookies  

_**recommendation**_: set cookies.keys and cookies.short.signed = true  


_**default value**_:
```js
{
  httpOnly: true,
  maxAge: 600000,
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

### dynamicScopes

Array of the dynamic scope values that the OP supports. These must be regular expressions that the OP will check string scope values, that aren't in the static list, against.   
  


_**default value**_:
```js
[]
```
<a id="dynamic-scopes-to-enable-a-dynamic-scope-values-like-api-write-hex-id-and-api-read-hex-id"></a><details><summary>(Click to expand) To enable a dynamic scope values like `api:write:{hex id}` and `api:read:{hex id}`</summary><br>


Configure `dynamicScopes` like so:
  

```js
[
  /^api:write:[a-fA-F0-9]{2,}$/,
  /^api:read:[a-fA-F0-9]{2,}$/,
]
```
</details>

### expiresWithSession

Function used to decide whether the given authorization code/ device code or implicit returned access token be bound to the user session. This will be applied to all tokens issued from the authorization / device code in the future. When tokens are session-bound the session will be loaded by its `uid` every time the token is encountered. Session bound tokens will effectively get revoked if the end-user logs out.  


_**default value**_:
```js
async function expiresWithSession(ctx, token) {
  return !token.scopes.has('offline_access');
}
```

### extraAccessTokenClaims

Function used to get additional access token claims when it is being issued. These claims will be available in your storage under property `extra`, returned by introspection as top level claims and pushed into `jwt`, `jwt-ietf` and `paseto` formatted tokens as top level claims as well. Returned claims may not overwrite other top level claims.   
  


_**default value**_:
```js
async function extraAccessTokenClaims(ctx, token) {
  return undefined;
}
```
<a id="extra-access-token-claims-to-push-additional-claims-to-an-access-token"></a><details><summary>(Click to expand) To push additional claims to an Access Token
</summary><br>

```js
{
  extraAccessTokenClaims(ctx, token) {
    return {
      'urn:oidc-provider:example:foo': 'bar',
    };
  }
}
```
</details>

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
function extraClientMetadataValidator(key, value, metadata, ctx) {
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
<a id="extra-client-metadata-validator-using-extra-client-metadata-to-allow-software-statement-dynamic-client-registration-property"></a><details><summary>(Click to expand) Using extraClientMetadata to allow software_statement dynamic client registration property
</summary><br>

```js
// npm install jose@2
const { JWT: { verify }, JWK } = require('jose');
const {
  errors: { InvalidSoftwareStatement, UnapprovedSoftwareStatement },
} = require('oidc-provider');
const softwareStatementKey = JWK.asKey(require('path/to/public/key'))
{
  extraClientMetadata: {
    properties: ['software_statement'],
    validator(key, value, metadata) {
      if (key === 'software_statement') {
        if (value === undefined) return;
        // software_statement is not stored, but used to convey client metadata
        delete metadata.software_statement;
        let payload;
        try {
          // extraClientMetadata.validator must be sync :sadface:
          payload = verify(value, softwareStatementKey, {
            algorithms: ['PS256'],
            issuer: 'Software Statement Issuer',
          });
          // additional custom validation function
          if (!approvedStatement(value, payload)) {
            throw new UnapprovedSoftwareStatement('software_statement not approved for use');
          }
          // cherry pick the software_statement values and assign them
          // Note: there will be no further validation ran on those values, so make sure
          //   they're conform
          const { client_name, client_uri } = payload;
          Object.assign(metadata, { client_name, client_uri });
        } catch (err) {
          throw new InvalidSoftwareStatement('could not verify software_statement');
        }
      }
    }
  }
}
```
</details>

### extraParams

Pass an iterable object (i.e. Array or Set of strings) to extend the parameters recognised by the authorization and device authorization endpoints. These parameters are then available in `ctx.oidc.params` as well as passed to interaction session details  


_**default value**_:
```js
[]
```

### formats

This option allows to configure the token serialization format. The different values change how a client-facing token value is generated as well as what properties get sent to the adapter for storage.
 - `opaque` (default) formatted tokens store every property as a root property in your adapter
 - `jwt` formatted tokens are issued as JWTs and stored the same as `opaque` only with additional property `jwt`. See `formats.jwtAccessTokenSigningAlg` for resolving the JWT Access Token signing algorithm. Note this is a proprietary format that will eventually get deprecated in favour of the 'jwt-ietf' value (once it gets stable and close to being an RFC)
 - `jwt-ietf` formatted tokens are issued as JWTs and stored the same as `opaque` only with additional property `jwt-ietf`. See `formats.jwtAccessTokenSigningAlg` for resolving the JWT Access Token signing algorithm. This is an implementation of [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-05) draft and to enable it you need to enable `features.ietfJWTAccessTokenProfile`. 'jwt-ietf' value (once it gets stable and close to being an RFC)
 - `paseto` formatted tokens are issued as v2.public PASETOs and stored the same as `opaque` only with additional property `paseto`. The server must have an `OKP Ed25519` key available to sign with else it will throw a server error. PASETOs are also allowed to only have a single audience, if the token's "aud" resolves with more than one the server will throw a server error. **This format is only supported in node runtime >= 12.0.0**
 - the value may also be a function dynamically determining the format (returning either `jwt`, `jwt-ietf`, `paseto` or `opaque` depending on the token itself)   
  


_**default value**_:
```js
{
  AccessToken: 'opaque',
  ClientCredentials: 'opaque',
  customizers: {
    'jwt-ietf': undefined,
    jwt: undefined,
    paseto: undefined
  },
  jwtAccessTokenSigningAlg: [AsyncFunction: jwtAccessTokenSigningAlg] // see expanded details below
}
```
<a id="formats-to-enable-jwt-access-tokens"></a><details><summary>(Click to expand) To enable JWT Access Tokens</summary><br>


Configure `formats`:
  

```js
{ AccessToken: 'jwt' }
```
</details>
<a id="formats-to-enable-paseto-v-2-public-access-tokens"></a><details><summary>(Click to expand) To enable PASETO v2.public Access Tokens</summary><br>


Configure `formats`:
  

```js
{ AccessToken: 'paseto' }
```
</details>
<a id="formats-to-dynamically-decide-on-the-format-used-e-g-only-if-it-is-intended-for-a-resource"></a><details><summary>(Click to expand) To dynamically decide on the format used, e.g. only if it is intended for a resource</summary><br>


server Configure `formats`:
  

```js
{
  AccessToken(ctx, token) {
    return token.aud ? 'jwt' : 'opaque';
  }
}
```
</details>

### formats.customizers

Functions used before signing a structured Access Token of a given type, such as a JWT or PASETO one. Customizing here only changes the structured Access Token, not your storage, introspection or anything else. For such extras use [`extraAccessTokenClaims`](#extraaccesstokenclaims) instead.   
  


_**default value**_:
```js
{
  'jwt-ietf': undefined,
  jwt: undefined,
  paseto: undefined
}
```
<a id="formats-customizers-to-push-additional-claims-to-a-jwt-format-access-token-payload"></a><details><summary>(Click to expand) To push additional claims to a `jwt` format Access Token payload
</summary><br>

```js
{
  customizers: {
    async jwt(ctx, token, jwt) {
      jwt.payload.foo = 'bar';
    }
  }
}
```
</details>
<a id="formats-customizers-to-push-additional-headers-to-a-jwt-format-access-token"></a><details><summary>(Click to expand) To push additional headers to a `jwt` format Access Token
</summary><br>

```js
{
  customizers: {
    async jwt(ctx, token, jwt) {
      jwt.header = { foo: 'bar' };
    }
  }
}
```
</details>
<a id="formats-customizers-to-push-additional-claims-to-a-jwt-ietf-format-access-token-payload"></a><details><summary>(Click to expand) To push additional claims to a `jwt-ietf` format Access Token payload
</summary><br>

```js
{
  customizers: {
    async ['jwt-ietf'](ctx, token, jwt) {
      jwt.payload.foo = 'bar';
    }
  }
}
```
</details>
<a id="formats-customizers-to-push-additional-headers-to-a-jwt-ietf-format-access-token"></a><details><summary>(Click to expand) To push additional headers to a `jwt-ietf` format Access Token
</summary><br>

```js
{
  customizers: {
    async ['jwt-ietf'](ctx, token, jwt) {
      jwt.header = { foo: 'bar' };
    }
  }
}
```
</details>
<a id="formats-customizers-to-push-a-payload-and-a-footer-to-a-paseto-structured-access-token"></a><details><summary>(Click to expand) To push a payload and a footer to a PASETO structured access token
</summary><br>

```js
{
  customizers: {
    paseto(ctx, token, structuredToken) {
      structuredToken.payload.foo = 'bar';
      structuredToken.footer = 'foo'
      structuredToken.footer = Buffer.from('foo')
      structuredToken.footer = { foo: 'bar' } // will get stringified
    }
  }
}
```
</details>

### formats.jwtAccessTokenSigningAlg

Function used to resolve a JWT Access Token signing algorithm. The resolved algorithm must be an asymmetric one supported by the provider's keys in jwks.  


_**default value**_:
```js
async function jwtAccessTokenSigningAlg(ctx, token, client) {
  if (client && client.idTokenSignedResponseAlg !== 'none' && !client.idTokenSignedResponseAlg.startsWith('HS')) {
    return client.idTokenSignedResponseAlg;
  }
  return 'RS256';
}
```

### httpOptions

Function called whenever calls to an external HTTP(S) resource are being made. Use this to change the [got](https://github.com/sindresorhus/got/tree/v9.6.0) library's request options as these requests are being made. This can be used to e.g. Change the request timeout option or to configure the global agent to use HTTP_PROXY and HTTPS_PROXY environment variables.   
  


_**default value**_:
```js
function httpOptions(options) {
  options.followRedirect = false;
  options.headers['User-Agent'] = 'oidc-provider/${VERSION} (${ISSUER_IDENTIFIER})';
  options.retry = 0;
  options.throwHttpErrors = false;
  options.timeout = 2500;
  return options;
}
```
<a id="http-options-to-change-the-request's-timeout"></a><details><summary>(Click to expand) To change the request's timeout</summary><br>


To change all request's timeout configure the httpOptions as a function like so:
  

```js
 {
   httpOptions(options) {
     options.timeout = 5000;
     return options;
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
  Prompt {
    name: 'login',
    requestable: true,
    details: (ctx) => {
      const { oidc } = ctx;

      return {
        ...(oidc.params.max_age === undefined ? { max_age: oidc.params.max_age } : undefined),
        ...(oidc.params.login_hint === undefined ? { login_hint: oidc.params.login_hint } : undefined),
        ...(oidc.params.id_token_hint === undefined ? { id_token_hint: oidc.params.id_token_hint } : undefined),
      };
    },
    checks: [
      Check {
        reason: 'login_prompt',
        description: 'login prompt was not resolved',
        error: 'login_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          if (oidc.prompts.has(name) && oidc.promptPending(name)) {
            return true;
          }

          return false;
        }
      },
      Check {
        reason: 'no_session',
        description: 'End-User authentication is required',
        error: 'login_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          if (oidc.session.accountId()) {
            return false;
          }

          return true;
        }
      },
      Check {
        reason: 'max_age',
        description: 'End-User authentication could not be obtained',
        error: 'login_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          if (oidc.params.max_age === undefined) {
            return false;
          }

          if (!oidc.session.accountId()) {
            return true;
          }

          if (oidc.session.past(oidc.params.max_age) && (!ctx.oidc.result || !ctx.oidc.result.login)) {
            return true;
          }

          return false;
        }
      },
      Check {
        reason: 'id_token_hint',
        description: 'id_token_hint and authenticated subject do not match',
        error: 'login_required',
        details: () => {},
        check: async (ctx) => {
          const { oidc } = ctx;
          if (oidc.entities.IdTokenHint === undefined) {
            return false;
          }

          const { payload } = oidc.entities.IdTokenHint;

          let sub = oidc.session.accountId();
          if (sub === undefined) {
            return true;
          }

          if (oidc.client.sectorIdentifier) {
            sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(ctx, sub, oidc.client);
          }

          if (payload.sub !== sub) {
            return true;
          }

          return false;
        }
      },
      Check {
        reason: 'claims_id_token_sub_value',
        description: 'requested subject could not be obtained',
        error: 'login_required',
        details: ({ oidc }) => ({ sub: oidc.claims.id_token.sub }),
        check: async (ctx) => {
          const { oidc } = ctx;
          if (!has(oidc.claims, 'id_token.sub.value')) {
            return false;
          }

          let sub = oidc.session.accountId();
          if (sub === undefined) {
            return true;
          }

          if (oidc.client.sectorIdentifier) {
            sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(ctx, sub, oidc.client);
          }

          if (oidc.claims.id_token.sub.value !== sub) {
            return true;
          }

          return false;
        }
      },
      Check {
        reason: 'essential_acrs',
        description: 'none of the requested ACRs could not be obtained',
        error: 'login_required',
        details: ({ oidc }) => ({ acr: oidc.claims.id_token.acr }),
        check: (ctx) => {
          const { oidc } = ctx;
          const request = get(oidc.claims, 'id_token.acr', {});

          if (!request || !request.essential || !request.values) {
            return false;
          }

          if (!Array.isArray(oidc.claims.id_token.acr.values)) {
            throw new errors.InvalidRequest('invalid claims.id_token.acr.values type');
          }

          if (request.values.includes(oidc.acr)) {
            return false;
          }

          return true;
        }
      },
      Check {
        reason: 'essential_acr',
        description: 'requested ACR could not be obtained',
        error: 'login_required',
        details: ({ oidc }) => ({ acr: oidc.claims.id_token.acr }),
        check: (ctx) => {
          const { oidc } = ctx;
          const request = get(oidc.claims, 'id_token.acr', {});

          if (!request || !request.essential || !request.value) {
            return false;
          }

          if (request.value === oidc.acr) {
            return false;
          }

          return true;
        }
      }
    ]
  },
  Prompt {
    name: 'consent',
    requestable: true,
    details: (ctx) => {
      const { oidc } = ctx;

      const acceptedScopes = oidc.session.acceptedScopesFor(oidc.params.client_id);
      const rejectedScopes = oidc.session.rejectedScopesFor(oidc.params.client_id);
      const acceptedClaims = oidc.session.acceptedClaimsFor(oidc.params.client_id);
      const rejectedClaims = oidc.session.rejectedClaimsFor(oidc.params.client_id);

      const details = {
        scopes: {
          new: [...oidc.requestParamScopes]
            .filter(x => !acceptedScopes.has(x) && !rejectedScopes.has(x)),
          accepted: [...acceptedScopes],
          rejected: [...rejectedScopes],
        },
        claims: {
          new: [...oidc.requestParamClaims]
            .filter(x => !acceptedClaims.has(x) && !rejectedClaims.has(x)),
          accepted: [...acceptedClaims],
          rejected: [...rejectedClaims],
        },
      };

      return omitBy(details, val => val === undefined);
    },
    checks: [
      Check {
        reason: 'consent_prompt',
        description: 'consent prompt was not resolved',
        error: 'consent_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          if (oidc.prompts.has(name) && oidc.promptPending(name)) {
            return true;
          }

          return false;
        }
      },
      Check {
        reason: 'client_not_authorized',
        description: 'client not authorized for End-User session yet',
        error: 'interaction_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          if (oidc.session.sidFor(oidc.client.clientId)) {
            return false;
          }

          return true;
        }
      },
      Check {
        reason: 'native_client_prompt',
        description: 'native clients require End-User interaction',
        error: 'interaction_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          if (
            oidc.client.applicationType === 'native'
            && oidc.params.response_type !== 'none'
            && (!oidc.result || !('consent' in oidc.result))
          ) {
            return true;
          }

          return false;
        }
      },
      Check {
        reason: 'scopes_missing',
        description: 'requested scopes not granted by End-User',
        error: 'consent_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          const promptedScopes = oidc.session.promptedScopesFor(oidc.client.clientId);

          for (const scope of oidc.requestParamScopes) { // eslint-disable-line no-restricted-syntax
            if (!promptedScopes.has(scope)) {
              return true;
            }
          }

          return false;
        }
      },
      Check {
        reason: 'claims_missing',
        description: 'requested claims not granted by End-User',
        error: 'consent_required',
        details: () => {},
        check: (ctx) => {
          const { oidc } = ctx;
          const promptedClaims = oidc.session.promptedClaimsFor(oidc.client.clientId);

          for (const claim of oidc.requestParamClaims) { // eslint-disable-line no-restricted-syntax
            if (!promptedClaims.has(claim) && !['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim)) {
              return true;
            }
          }

          return false;
        }
      }
    ]
  }
]

```
<a id="interactions-policy-default-interaction-policy-description"></a><details><summary>(Click to expand) default interaction policy description</summary><br>


The default interaction policy consists of two available prompts, login and consent <br/><br/>
 - `login` does the following checks:
 - no_session - checks that there's an established session, a authenticated end-user
 - max_age - processes the max_age parameter (when the session's auth_time is too old it requires login)
 - id_token_hint - processes the id_token_hint parameter (when the end-user sub differs it requires login)
 - claims_id_token_sub_value - processes the claims parameter `sub` (when the `claims` parameter requested sub differs it requires login)
 - essential_acrs - processes the claims parameter `acr` (when the current acr is not amongst the `claims` parameter essential `acr.values` it requires login)
 - essential_acr - processes the claims parameter `acr` (when the current acr is not equal to the `claims` parameter essential `acr.value` it requires login) <br/><br/>
 - `consent` does the following checks:
 - client_not_authorized - every client needs to go through a consent once per end-user session
 - native_client_prompt - native clients always require re-consent
 - scopes_missing - when requested scope includes scope values previously not requested it requests consent
 - claims_missing - when requested claims parameter includes claims previously not requested it requests consent <br/><br/> These checks are the best practice for various privacy and security reasons.  


</details>
<a id="interactions-policy-disabling-default-checks"></a><details><summary>(Click to expand) disabling default checks</summary><br>


You may be required to skip (silently accept) some of the consent checks, while it is discouraged there are valid reasons to do that, for instance in some first-party scenarios or going with pre-existing, previously granted, consents. Definitely do not just remove the checks, remove and add ones that do the same operation with the exception of those scenarios you want to skip and in those you'll have to call some of the methods ran by the `returnTo` / `resume` flow by default to ensure smooth operation.
 - `ctx.oidc.session.ensureClientContainer(clientId<string>)` ensures the client namespace in the session is set up
 - `ctx.oidc.session.promptedScopesFor(clientId<string>, scopes<Set|Array>)` - the scopes that were already prompted before hand
 - `ctx.oidc.session.promptedClaimsFor(clientId<string>, claims<Set|Array>)`- the claims that were already prompted before hand
 - `ctx.oidc.session.rejectedScopesFor(clientId<string>, scopes<Set|Array>)` - the scopes that were already prompted before hand but were rejected
 - `ctx.oidc.session.rejectedClaimsFor(clientId<string>, claims<Set|Array>)` - the claims that were already prompted before hand but were rejected  


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
  return `/interaction/${ctx.oidc.uid}`;
}
```

### introspectionEndpointAuthMethods

Array of Client Authentication methods supported by this OP's Introspection Endpoint. If no configuration value is provided the same values as for tokenEndpointAuthMethods will be used. Supported values list is the same as for tokenEndpointAuthMethods.  


_**default value**_:
```js
[
  'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt'
]
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


... If a client has the grant whitelisted and scope includes offline_access or the client is a public web client doing code flow. Configure `issueRefreshToken` like so
  

```js
async issueRefreshToken(ctx, client, code) {
  if (!client.grantTypeAllowed('refresh_token')) {
    return false;
  }
  return code.scopes.has('offline_access') || (client.applicationType === 'web' && client.tokenEndpointAuthMethod === 'none');
}
```
</details>

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

PKCE configuration such as available methods and policy check on required use of PKCE  


### pkce.methods

fine-tune the supported code challenge methods. Supported values are
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
  return client.applicationType === 'native';
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

Array of response_type values that OP supports. The default omits all response types that result in access tokens being issued by the authorization endpoint directly as per [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.1.2) You can still enable them if you need to.   
  


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

### revocationEndpointAuthMethods

Array of Client Authentication methods supported by this OP's Revocation Endpoint. If no configuration value is provided the same values as for tokenEndpointAuthMethods will be used. Supported values list is the same as for tokenEndpointAuthMethods.  


_**default value**_:
```js
[
  'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt'
]
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
  check_session: '/session/check',
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

Array of the scope values that the OP supports  


_**default value**_:
```js
[
  'openid',
  'offline_access'
]
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
  'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt'
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

Expirations (in seconds, or dynamically returned value) for all token types   
  

_**recommendation**_: Do not set token TTLs longer then they absolutely have to be, the shorter the TTL, the better. Rather than setting crazy high Refresh Token TTL look into `rotateRefreshToken` configuration option which is set up in way that when refresh tokens are regularly used they will have their TTL refreshed (via rotation). This is inline with the [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13)  


_**default value**_:
```js
{
  AccessToken: 3600,
  AuthorizationCode: 600,
  ClientCredentials: 600,
  DeviceCode: 600,
  IdToken: 3600,
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
  }
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

### whitelistedJWA

Fine-tune the algorithms your provider will support by declaring algorithm values for each respective JWA use  

_**recommendation**_: Only allow JWA algs that are necessary. The current defaults are based on recommendations from the [JWA specification](https://tools.ietf.org/html/rfc7518) + enables RSASSA-PSS based on current guidance in FAPI. "none" JWT algs are disabled by default but available if you need them.  


### whitelistedJWA.authorizationEncryptionAlgValues

JWA algorithms the provider supports to wrap keys for JWT Authorization response encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A256KW',
  'RSA-OAEP'
]
```
<a id="whitelisted-jwa-authorization-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based (note: RSA-OAEP-* is only supported in node runtime >= 12.9.0)
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

### whitelistedJWA.authorizationEncryptionEncValues

JWA algorithms the provider supports to encrypt JWT Authorization Responses with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="whitelisted-jwa-authorization-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### whitelistedJWA.authorizationSigningAlgValues

JWA algorithms the provider supports to sign JWT Authorization Responses with   
  


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
<a id="whitelisted-jwa-authorization-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.dPoPSigningAlgValues

JWA algorithms the provider supports to verify DPoP Proof JWTs with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'EdDSA'
]
```
<a id="whitelisted-jwa-d-po-p-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.idTokenEncryptionAlgValues

JWA algorithms the provider supports to wrap keys for ID Token encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A256KW',
  'RSA-OAEP'
]
```
<a id="whitelisted-jwa-id-token-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based (note: RSA-OAEP-* is only supported in node runtime >= 12.9.0)
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

### whitelistedJWA.idTokenEncryptionEncValues

JWA algorithms the provider supports to encrypt ID Tokens with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="whitelisted-jwa-id-token-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### whitelistedJWA.idTokenSigningAlgValues

JWA algorithms the provider supports to sign ID Tokens with   
  


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
<a id="whitelisted-jwa-id-token-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.introspectionEncryptionAlgValues

JWA algorithms the provider supports to wrap keys for JWT Introspection response encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A256KW',
  'RSA-OAEP'
]
```
<a id="whitelisted-jwa-introspection-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based (note: RSA-OAEP-* is only supported in node runtime >= 12.9.0)
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

### whitelistedJWA.introspectionEncryptionEncValues

JWA algorithms the provider supports to encrypt JWT Introspection responses with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="whitelisted-jwa-introspection-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### whitelistedJWA.introspectionEndpointAuthSigningAlgValues

JWA algorithms the provider supports on the introspection endpoint   
  


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
<a id="whitelisted-jwa-introspection-endpoint-auth-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.introspectionSigningAlgValues

JWA algorithms the provider supports to sign JWT Introspection responses with   
  


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
<a id="whitelisted-jwa-introspection-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.requestObjectEncryptionAlgValues

JWA algorithms the provider supports to receive encrypted Request Object keys wrapped with   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A256KW',
  'RSA-OAEP'
]
```
<a id="whitelisted-jwa-request-object-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based (note: RSA-OAEP-* is only supported in node runtime >= 12.9.0)
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

### whitelistedJWA.requestObjectEncryptionEncValues

JWA algorithms the provider supports decrypt Request Objects with encryption   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="whitelisted-jwa-request-object-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### whitelistedJWA.requestObjectSigningAlgValues

JWA algorithms the provider supports to receive Request Objects with   
  


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
<a id="whitelisted-jwa-request-object-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.revocationEndpointAuthSigningAlgValues

JWA algorithms the provider supports on the revocation endpoint   
  


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
<a id="whitelisted-jwa-revocation-endpoint-auth-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.tokenEndpointAuthSigningAlgValues

JWA algorithms the provider supports on the token endpoint   
  


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
<a id="whitelisted-jwa-token-endpoint-auth-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
]
```
</details>

### whitelistedJWA.userinfoEncryptionAlgValues

JWA algorithms the provider supports to wrap keys for UserInfo Response encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A256KW',
  'RSA-OAEP'
]
```
<a id="whitelisted-jwa-userinfo-encryption-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  // asymmetric RSAES based (note: RSA-OAEP-* is only supported in node runtime >= 12.9.0)
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

### whitelistedJWA.userinfoEncryptionEncValues

JWA algorithms the provider supports to encrypt UserInfo responses with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="whitelisted-jwa-userinfo-encryption-enc-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

### whitelistedJWA.userinfoSigningAlgValues

JWA algorithms the provider supports to sign UserInfo responses with   
  


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
<a id="whitelisted-jwa-userinfo-signing-alg-values-supported-values-list"></a><details><summary>(Click to expand) Supported values list
</summary><br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA', // (note: EdDSA is only supported in node runtime >= 12.0.0)
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
https://tools.ietf.org/html/rfc6749#section-2.3.1 incl.
https://tools.ietf.org/html/rfc6749#appendix-B

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

### I'm getting an client authentication failed error with no details

Every client is configured with one of 7 available
[`token_endpoint_auth_method` values](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method)
and it must adhere to how that given method must be submitted. Submitting multiple means of
authentication is also not possible. If you're a provider operator you're encouraged to set up
listeners for errors
(see [events.md](https://github.com/panva/node-oidc-provider/blob/master/docs/events.md)) and
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
const signedIn = !!session.account
```

### Client Credentials only clients

You're getting the `redirect_uris is mandatory property` error but Client Credential clients
(Resource Servers) don't need `redirect_uris` or `response_types`... You're getting this error
because they are required properties, but they can be empty...

```js
{
  redirect_uris: [],
  response_types: [],
  grant_types: ['client_credentials']
}
```


[support-sponsor]: https://github.com/sponsors/panva
[sponsor-auth0]: https://auth0.com/developers?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=oidc-provider&utm_content=auth
