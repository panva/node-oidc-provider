# oidc-provider API documentation

oidc-provider allows to be extended and configured in various ways to fit a variety of use cases. You
will have to configure your instance with how to find your user accounts, where to store and retrieve
persisted data from and where your end-user interactions happen. The [example](/example) application
is a good starting point to get an idea of what you should provide.

## Sponsor

[<img width="65" height="65" align="left" src="https://avatars.githubusercontent.com/u/2824157?s=75&v=4" alt="auth0-logo">][sponsor-auth0] If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan at [auth0.com/overview][sponsor-auth0].<br><br>

## Support

[<img src="https://c5.patreon.com/external/logo/become_a_patron_button@2x.png" width="160" align="right">][support-patreon]
If you or your business use oidc-provider, please consider becoming a [Patron][support-patreon] so I can continue maintaining it and adding new features carefree. You may also donate one-time via [PayPal][support-paypal].
[<img src="https://cdn.jsdelivr.net/gh/gregoiresgt/payment-icons@183140a5ff8f39b5a19d59ebeb2c77f03c3a24d3/Assets/Payment/PayPal/Paypal@2x.png" width="100" align="right">][support-paypal]

<br>

---

**Table of Contents**

- [Basic configuration example](#basic-configuration-example)
- [Default configuration values](#default-configuration-values)
- [Accounts](#accounts)
- [User flows](#user-flows)
- [Custom Grant Types](#custom-grant-types)
- [Registering module middlewares (helmet, ip-filters, rate-limiters, etc)](#registering-module-middlewares-helmet-ip-filters-rate-limiters-etc)
- [Pre- and post-middlewares](#pre--and-post-middlewares)
- [Mounting oidc-provider](#mounting-oidc-provider)
  - [to an express application](#to-an-express-application)
  - [to a koa application](#to-a-koa-application)
- [Trusting TLS offloading proxies](#trusting-tls-offloading-proxies)
- [Configuration options](#configuration-options)
  - [adapter](#adapter)
  - [clients](#clients)
  - [findAccount](#findaccount)
  - [jwks](#jwks)
  - [features](#features)
    - [backchannelLogout](#featuresbackchannellogout)
    - [certificateBoundAccessTokens](#featurescertificateboundaccesstokens)
    - [claimsParameter](#featuresclaimsparameter)
    - [clientCredentials](#featuresclientcredentials)
    - [devInteractions](#featuresdevinteractions)
    - [deviceFlow](#featuresdeviceflow)
    - [encryption](#featuresencryption)
    - [frontchannelLogout](#featuresfrontchannellogout)
    - [introspection](#featuresintrospection)
    - [jwtIntrospection](#featuresjwtintrospection)
    - [jwtResponseModes](#featuresjwtresponsemodes)
    - [registration](#featuresregistration)
    - [registrationManagement](#featuresregistrationmanagement)
    - [request](#featuresrequest)
    - [requestUri](#featuresrequesturi)
    - [resourceIndicators](#featuresresourceindicators)
    - [revocation](#featuresrevocation)
    - [sessionManagement](#featuressessionmanagement)
    - [webMessageResponseMode](#featureswebmessageresponsemode)
  - [acrValues](#acrvalues)
  - [audiences](#audiences)
  - [claims](#claims)
  - [clientBasedCORS](#clientbasedcors)
  - [clientDefaults](#clientdefaults)
  - [clockTolerance](#clocktolerance)
  - [conformIdTokenClaims](#conformidtokenclaims)
  - [cookies](#cookies)
  - [discovery](#discovery)
  - [dynamicScopes](#dynamicscopes)
  - [expiresWithSession](#expireswithsession)
  - [extraClientMetadata](#extraclientmetadata)
  - [extraParams](#extraparams)
  - [formats](#formats)
  - [httpOptions](#httpoptions)
  - [interactions](#interactions)
  - [interactionUrl](#interactionurl)
  - [introspectionEndpointAuthMethods](#introspectionendpointauthmethods)
  - [issueRefreshToken](#issuerefreshtoken)
  - [logoutSource](#logoutsource)
  - [pairwiseIdentifier](#pairwiseidentifier)
  - [pkceMethods](#pkcemethods)
  - [postLogoutSuccessSource](#postlogoutsuccesssource)
  - [renderError](#rendererror)
  - [responseTypes](#responsetypes)
  - [revocationEndpointAuthMethods](#revocationendpointauthmethods)
  - [rotateRefreshToken](#rotaterefreshtoken)
  - [routes](#routes)
  - [scopes](#scopes)
  - [subjectTypes](#subjecttypes)
  - [tokenEndpointAuthMethods](#tokenendpointauthmethods)
  - [ttl](#ttl)
  - [whitelistedJWA](#whitelistedjwa)



## Basic configuration example

```js
const Provider = require('oidc-provider');
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
user session, requested ACR not fulfilled, prompt requested, ...) it will resolve an `interactionUrl`
(configurable) and redirect the User-Agent to that url. Before doing so it will save a short-lived
session and dump its identifier into a cookie scoped to the resolved interaction path.

This session contains:

- details of the interaction that is required
- all authorization request parameters
- current session account ID should there be one
- the uid of the authorization request
- the url to redirect the user to once interaction is finished

oidc-provider expects that you resolve all future interactions in one go and only then redirect the
User-Agent back with the results

Once the required interactions are finished you are expected to redirect back to the authorization
endpoint, affixed by the uid of the original request and the interaction results stored in the
interaction session object.

The Provider instance comes with helpers that aid with getting interaction details as well as
packing the results. See them used in the [step-by-step](https://github.com/panva/node-oidc-provider-example)
or [in-repo](/example) examples.


**`#provider.interactionDetails(req)`**
```js
// with express
expressApp.get('/interaction/:uid', async (req, res) => {
  const details = await provider.interactionDetails(req);
  // ...
});

// with koa
router.get('/interaction/:uid', async (ctx, next) => {
  const details = await provider.interactionDetails(ctx.req);
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
for example to implement an [OAuth 2.0 Token Exchange][token-exchange]. You can check the standard
grant factories [here](/lib/actions/grants).

**Note: Since custom grant types are registered after instantiating a Provider instance they can
only be used by clients loaded by an adapter, statically configured clients will throw
InvalidClientMetadata errors.**

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
   * `certificates`
   * `check_session_origin`
   * `check_session`
   * `client_delete`
   * `client_update`
   * `client`
   * `code_verification`
   * `device_authorization`
   * `device_resume`
   * `discovery`
   * `end_session`
   * `end_session_confirm`
   * `end_session_success`
   * `introspection`
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
path prefix.

### to an express application
```js
// assumes express ^4.0.0
const prefix = '/oidc';
expressApp.use(prefix, oidc.callback);
```

### to a koa application
```js
// assumes koa ^2.0.0
const mount = require('koa-mount');
const prefix = '/oidc';
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

<!-- DO NOT EDIT, COMMIT OR STAGE CHANGES BELOW THIS LINE -->
<!-- START CONF OPTIONS -->
### adapter

The provided example and any new instance of oidc-provider will use the basic in-memory adapter for storing issued tokens, codes, user sessions, dynamically registered clients, etc. This is fine as long as you develop, configure and generally just play around since every time you restart your process all information will be lost. As soon as you cannot live with this limitation you will be required to provide your own custom adapter constructor for oidc-provider to use. This constructor will be called for every model accessed the first time it is needed. The API oidc-provider expects is documented [here](/example/my_adapter.js).   
  

<details>
  <summary>(Click to expand) MongoDB adapter implementation</summary>
  <br>


See [/example/adapters/mongodb.js](/example/adapters/mongodb.js)  


</details>
<details>
  <summary>(Click to expand) Redis adapter implementation</summary>
  <br>


See [/example/adapters/redis.js](/example/adapters/redis.js)  


</details>
<details>
  <summary>(Click to expand) Redis w/ ReJSON adapter implementation</summary>
  <br>


See [/example/adapters/redis_rejson.js](/example/adapters/redis_rejson.js)  


</details>
<details>
  <summary>(Click to expand) Default in-memory adapter implementation</summary>
  <br>


See [/lib/adapters/memory_adapter.js](/lib/adapters/memory_adapter.js)  


</details>

### clients

Array of objects representing client metadata. These clients are referred to as static, they don't expire, never reload, are always available. If the client metadata in this array is invalid the Provider instantiation will fail with an error. In addition to these clients the provider will use your adapter's `find` method when a non-cached client_id is encountered. If you only wish to support statically configured clients and no dynamic registration then make it so that your adapter resolves client find calls with a falsy value (e.g. `return Promise.resolve()`) and don't take unnecessary DB trips.   
 Client's metadata is validated as defined by the respective specification they've been defined in.   
  


_**default value**_:
```js
[]
```
<details>
  <summary>(Click to expand) Available Metadata</summary>
  <br>


application_type, client_id, client_name, client_secret, client_uri, contacts, default_acr_values, default_max_age, grant_types, id_token_signed_response_alg, initiate_login_uri, jwks, jwks_uri, logo_uri, policy_uri, post_logout_redirect_uris, redirect_uris, require_auth_time, response_types, scope, sector_identifier_uri, subject_type, token_endpoint_auth_method, tos_uri, userinfo_signed_response_alg <br/><br/>The following metadata is available but may not be recognized depending on your provider's configuration.<br/><br/> authorization_encrypted_response_alg, authorization_encrypted_response_enc, authorization_signed_response_alg, backchannel_logout_session_required, backchannel_logout_uri, frontchannel_logout_session_required, frontchannel_logout_uri, id_token_encrypted_response_alg, id_token_encrypted_response_enc, introspection_encrypted_response_alg, introspection_encrypted_response_enc, introspection_endpoint_auth_method, introspection_endpoint_auth_signing_alg, introspection_signed_response_alg, request_object_encryption_alg, request_object_encryption_enc, request_object_signing_alg, request_uris, revocation_endpoint_auth_method, revocation_endpoint_auth_signing_alg, tls_client_auth_san_dns, tls_client_auth_san_email, tls_client_auth_san_ip, tls_client_auth_san_uri, tls_client_auth_subject_dn, tls_client_certificate_bound_access_tokens, token_endpoint_auth_signing_alg, userinfo_encrypted_response_alg, userinfo_encrypted_response_enc, web_message_uris  


</details>

### findAccount

Helper used by the OP to load an account and retrieve its available claims. The return value should be a Promise and #claims() can return a Promise too  


_**default value**_:
```js
async findAccount(ctx, sub, token) {
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
 - OKP (Ed25519 and Ed448 curves)
 - EC (P-256, P-384 and P-521 curves)   
  

_**recommendation**_: **Provider key rotation** - The following action order is recommended when rotating signing keys on a distributed deployment with rolling reloads in place.
 1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become available for verification should they be encountered but not yet used for signing
 2. reload all your processes
 3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be used for signing after reload
 4. reload all your processes  

_**default value**_:
```js
{
  keys: [
    {
      alg: 'RS256',
      d: 'VEZOsY07JTFzGTqv6cC2Y32vsfChind2I_TTuvV225_-0zrSej3XLRg8iE_u0-3GSgiGi4WImmTwmEgLo4Qp3uEcxCYbt4NMJC7fwT2i3dfRZjtZ4yJwFl0SIj8TgfQ8ptwZbFZUlcHGXZIr4nL8GXyQT0CK8wy4COfmymHrrUoyfZA154ql_OsoiupSUCRcKVvZj2JHL2KILsq_sh_l7g2dqAN8D7jYfJ58MkqlknBMa2-zi5I0-1JUOwztVNml_zGrp27UbEU60RqV3GHjoqwI6m01U7K0a8Q_SQAKYGqgepbAYOA-P4_TLl5KC4-WWBZu_rVfwgSENwWNEhw8oQ',
      dp: 'E1Y-SN4bQqX7kP-bNgZ_gEv-pixJ5F_EGocHKfS56jtzRqQdTurrk4jIVpI-ZITA88lWAHxjD-OaoJUh9Jupd_lwD5Si80PyVxOMI2xaGQiF0lbKJfD38Sh8frRpgelZVaK_gm834B6SLfxKdNsP04DsJqGKktODF_fZeaGFPH0',
      dq: 'F90JPxevQYOlAgEH0TUt1-3_hyxY6cfPRU2HQBaahyWrtCWpaOzenKZnvGFZdg-BuLVKjCchq3G_70OLE-XDP_ol0UTJmDTT-WyuJQdEMpt_WFF9yJGoeIu8yohfeLatU-67ukjghJ0s9CBzNE_LrGEV6Cup3FXywpSYZAV3iqc',
      e: 'AQAB',
      kid: 'keystore-CHANGE-ME',
      kty: 'RSA',
      n: 'xwQ72P9z9OYshiQ-ntDYaPnnfwG6u9JAdLMZ5o0dmjlcyrvwQRdoFIKPnO65Q8mh6F_LDSxjxa2Yzo_wdjhbPZLjfUJXgCzm54cClXzT5twzo7lzoAfaJlkTsoZc2HFWqmcri0BuzmTFLZx2Q7wYBm0pXHmQKF0V-C1O6NWfd4mfBhbM-I1tHYSpAMgarSm22WDMDx-WWI7TEzy2QhaBVaENW9BKaKkJklocAZCxk18WhR0fckIGiWiSM5FcU1PY2jfGsTmX505Ub7P5Dz75Ygqrutd5tFrcqyPAtPTFDk8X1InxkkUwpP3nFU5o50DGhwQolGYKPGtQ-ZtmbOfcWQ',
      p: '5wC6nY6Ev5FqcLPCqn9fC6R9KUuBej6NaAVOKW7GXiOJAq2WrileGKfMc9kIny20zW3uWkRLm-O-3Yzze1zFpxmqvsvCxZ5ERVZ6leiNXSu3tez71ZZwp0O9gys4knjrI-9w46l_vFuRtjL6XEeFfHEZFaNJpz-lcnb3w0okrbM',
      q: '3I1qeEDslZFB8iNfpKAdWtz_Wzm6-jayT_V6aIvhvMj5mnU-Xpj75zLPQSGa9wunMlOoZW9w1wDO1FVuDhwzeOJaTm-Ds0MezeC4U6nVGyyDHb4CUA3ml2tzt4yLrqGYMT7XbADSvuWYADHw79OFjEi4T3s3tJymhaBvy1ulv8M',
      qi: 'wSbXte9PcPtr788e713KHQ4waE26CzoXx-JNOgN0iqJMN6C4_XJEX-cSvCZDf4rh7xpXN6SGLVd5ibIyDJi7bbi5EQ5AXjazPbLBjRthcGXsIuZ3AtQyR0CEWNSdM7EyM5TRdyZQ9kftfz9nI03guW3iKKASETqX2vh0Z8XRjyU',
      use: 'sig'
    }
  ]
}
```
<details>
  <summary>(Click to expand) Generating keys
</summary>
  <br>

```js
const { JWKS: { KeyStore } } = require('@panva/jose');
const keystore = new KeyStore();
keystore.generateSync('RSA', 2048, {
  alg: 'RS256',
  use: 'sig',
});
console.log('this is the full private JWKS:\n', keystore.toJWKS(true));
```
</details>
<details>
  <summary>(Click to expand) Generating keys for both signing and encryption</summary>
  <br>


Re-using the same keys for both encryption and signing is discouraged so it is best to generate one with `{ use: 'sig' }` and another with `{ use: 'enc' }`, e.g.
  

```js
const { JWKS: { KeyStore } } = require('@panva/jose');
const keystore = new KeyStore();
Promise.all([
  keystore.generate('RSA', 2048, {
    use: 'sig',
  }),
  keystore.generate('RSA', 2048, {
    use: 'enc',
  }),
  keystore.generate('EC', 'P-256', {
    use: 'sig',
  }),
  keystore.generate('EC', 'P-256', {
    use: 'enc',
  }),
  keystore.generate('OKP', 'Ed25519', {
    use: 'sig',
  }),
]).then(function () {
  console.log('this is the full private JWKS:\n', keystore.toJWKS(true));
});
```
</details>

### features

Enable/disable features. Some features are still either based on draft or experimental RFCs. Enabling those will produce a warning in your console and you must be aware that breaking changes may occur between draft implementations and that those will be published as minor versions of oidc-provider. See the example below on how to acknowledge the specification is a draft (this will remove the warning log) and ensure the provider instance will fail to instantiate if a new version of oidc-provider bundles newer version of the RFC with breaking changes in it.   
  

<details>
  <summary>(Click to expand) Acknowledging a draft / experimental feature
</summary>
  <br>

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
// NOTICE: You may disable this notice and these potentially breaking updates by acknowledging the current draft version. See https://github.com/panva/node-oidc-provider/tree/master/docs/README.md#features
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

[Back-Channel Logout 1.0 - draft 04](https://openid.net/specs/openid-connect-backchannel-1_0-04.html)  

Enables Back-Channel Logout features.   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.certificateBoundAccessTokens

[draft-ietf-oauth-mtls-14](https://tools.ietf.org/html/draft-ietf-oauth-mtls-14) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens  

Enables Certificate Bound Access Tokens. Clients may be registered with `tls_client_certificate_bound_access_tokens` to indicate intention to receive mutual TLS client certificate bound access tokens.   
  


_**default value**_:
```js
{
  enabled: false
}
```
<details>
  <summary>(Click to expand) Setting up the environment for Certificate Bound Access Tokens</summary>
  <br>


To enable Certificate Bound Access Tokens the provider expects your TLS-offloading proxy to handle the client certificate validation, parsing, handling, etc. Once set up you are expected to forward `x-ssl-client-cert` header with variable values set by this proxy. An important aspect is to sanitize the inbound request headers at the proxy. <br/><br/> The most common openssl based proxies are Apache and NGINX, with those you're looking to use <br/><br/> __`SSLVerifyClient` (Apache) / `ssl_verify_client` (NGINX)__ with the appropriate configuration value that matches your setup requirements. <br/><br/> Set the proxy request header with variable set as a result of enabling mutual TLS
  

```nginx
# NGINX
proxy_set_header x-ssl-client-cert $ssl_client_cert;
```
```apache
# Apache
RequestHeader set x-ssl-client-cert ""
RequestHeader set x-ssl-client-cert "%{SSL_CLIENT_CERT}s"
```
You should also consider hosting the endpoints supporting client authentication, on a separate host name or port in order to prevent unintended impact on the TLS behaviour of your other endpoints, e.g. Discovery or the authorization endpoint, by updating the discovery response to add [draft-ietf-oauth-mtls-14](https://tools.ietf.org/html/draft-ietf-oauth-mtls-14) specified `mtls_endpoint_aliases`.
  

```js
provider.use(async (ctx, next) => {
  await next();
  if (ctx.oidc.route === 'discovery') {
    ctx.body.mtls_endpoint_aliases = {};
    const endpointAuthMethodKeys = [
      'token_endpoint_auth_methods_supported',
      'introspection_endpoint_auth_methods_supported',
      'revocation_endpoint_auth_methods_supported',
    ];
    // splits `*_endpoint_auth_methods_supported` into two namespaces (mutual-TLS and regular);
    endpointAuthMethodKeys.forEach((key) => {
      if (ctx.body[key]) {
        ctx.body.mtls_endpoint_aliases[key] = ctx.body[key].filter(k => k.endsWith('tls_client_auth'));
        ctx.body[key] = ctx.body[key].filter(k => !ctx.body.mtls_endpoint_aliases[key].includes(k));
      }
    });
    const mtlsEndpoints = [
      'userinfo_endpoint',
      'token_endpoint',
      'introspection_endpoint',
      'revocation_endpoint',
      'device_authorization_endpoint',
    ];
    // aliases endpoints accepting client certificates in `mtls_endpoint_aliases`
    const mtlsOrigin = 'https://mtls.op.example.com';
    mtlsEndpoints.forEach((key) => {
      if (ctx.body[key]) {
        ctx.body.mtls_endpoint_aliases[key] = `${mtlsOrigin}${url.parse(ctx.body[key]).pathname}`;
      }
    });
  }
});
```
When doing that be sure to remove the client provided headers of the same name on the non-mutual TLS enabled host name / port in your proxy setup or block the routes for these there completely.  


</details>

### features.claimsParameter

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.5) - Requesting Claims using the "claims" Request Parameter  

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

[draft-ietf-oauth-device-flow-15](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15) - OAuth 2.0 Device Authorization Grant  

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
  userCodeInputSource: [AsyncFunction: userCodeInputSource]
}
```
<details>
  <summary>(Click to expand) features.deviceFlow options details</summary>
  <br>


#### charset

alias for a character set of the generated user codes. Supported values are
 - `base-20` uses BCDFGHJKLMNPQRSTVWXZ
 - `digits` uses 0123456789  


_**default value**_:
```js
'base-20'
```

#### deviceInfo

Helper function used to extract details from the device authorization endpoint request. This is then available during the end-user confirm screen and is supposed to aid the user confirm that the particular authorization initiated by the user from a device in his possession  


_**default value**_:
```js
deviceInfo(ctx) {
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
async successSource(ctx) {
  // @param ctx - koa request context
  const {
    clientId, clientName, clientUri, initiateLoginUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client;
  ctx.body = `<!DOCTYPE html>
ead>
<title>Sign-in Success</title>
<style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
head>
ody>
<div>
  <h1>Sign-in Success</h1>
  <p>Your sign-in ${clientName ? `with ${clientName}` : ''} was successful, you can now close this page.</p>
</div>
body>
html>`;
}
```

#### userCodeConfirmSource

HTML source rendered when device code feature renders an a confirmation prompt for ther User-Agent.  


_**default value**_:
```js
async userCodeConfirmSource(ctx, form, client, deviceInfo, userCode) {
  // @param ctx - koa request context
  // @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
  //   submitted by the End-User.
  // @param deviceInfo - device information from the device_authorization_endpoint call
  // @param userCode - formatted user code by the configured mask
  const {
    clientId, clientName, clientUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client;
  ctx.body = `<!DOCTYPE html>
ead>
<title>Device Login Confirmation</title>
<style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
head>
ody>
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
body>
html>`;
}
```

#### userCodeInputSource

HTML source rendered when device code feature renders an input prompt for the User-Agent.  


_**default value**_:
```js
async userCodeInputSource(ctx, form, out, err) {
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
ead>
<title>Sign-in</title>
<style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
head>
ody>
<div>
  <h1>Sign-in</h1>
  ${msg}
  ${form}
  <button type="submit" form="op.deviceInputForm">Continue</button>
</div>
body>
html>`;
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

### features.frontchannelLogout

[Front-Channel Logout 1.0 - draft 02](https://openid.net/specs/openid-connect-frontchannel-1_0-02.html)  

Enables Front-Channel Logout features  


_**default value**_:
```js
{
  enabled: false,
  logoutPendingSource: [AsyncFunction: logoutPendingSource]
}
```
<details>
  <summary>(Click to expand) features.frontchannelLogout options details</summary>
  <br>


#### logoutPendingSource

HTML source rendered when there are pending front-channel logout iframes to be called to trigger RP logouts. It should handle waiting for the frames to be loaded as well as have a timeout mechanism in it.  


_**default value**_:
```js
async logoutPendingSource(ctx, frames, postLogoutRedirectUri) {
  ctx.body = `<!DOCTYPE html>
ead>
<title>Logout</title>
<style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
head>
ody>
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
body>
html>`;
}
```

</details>

### features.introspection

[RFC7662](https://tools.ietf.org/html/rfc7662) - OAuth 2.0 Token Introspection  

Enables Token Introspection features   
  


_**default value**_:
```js
{
  enabled: false
}
```

### features.jwtIntrospection

[draft-ietf-oauth-jwt-introspection-response-03](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-03) - JWT Response for OAuth Token Introspection  

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
  secretFactory: [Function: secretFactory]
}
```
<details>
  <summary>(Click to expand) features.registration options details</summary>
  <br>


#### idFactory

helper generating random client identifiers during dynamic client registration  


_**default value**_:
```js
idFactory() {
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
<details>
  <summary>(Click to expand) To add an adapter backed initial access token and retrive its value
</summary>
  <br>

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
<details>
  <summary>(Click to expand) To define registration and registration management policies</summary>
  <br>


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
<details>
  <summary>(Click to expand) Using Initial Access Token policies for software_statement dynamic client registration property</summary>
  <br>


Support modules:
  

```js
const { verify } = require('jsonwebtoken');
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
     const softwareStatementKey = await loadKeyForThisPolicy();
     const statement = metadata.software_statement;
     let payload;
     try {
       payload = verify(value, softwareStatementKey, {
         algorithms: ['RS256'],
         issuer: 'Software Statement Issuer',
       });
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

helper generating random client secrets during dynamic client registration  


_**default value**_:
```js
secretFactory() {
  return base64url(crypto.randomBytes(64)); // 512 base64url random bits
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
<details>
  <summary>(Click to expand) features.registrationManagement options details</summary>
  <br>


#### rotateRegistrationAccessToken

Enables registration access token rotation. The provider will discard the current Registration Access Token with a successful update and issue a new one, returning it to the client with the Registration Update Response. Supported values are
 - `false` registration access tokens are not rotated
 - `true` registration access tokens are rotated when used
 - function returning true/false, true when rotation should occur, false when it shouldn't  


_**default value**_:
```js
false
```
<details>
  <summary>(Click to expand) function use
</summary>
  <br>

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

### features.request

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.1) - Passing a Request Object by Value  

Enables the use and validations of `request` parameter  


_**default value**_:
```js
{
  enabled: false
}
```

### features.requestUri

[Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2) - Passing a Request Object by Reference  

Enables the use and validations of `request_uri` parameter  


_**default value**_:
```js
{
  enabled: true,
  requireUriRegistration: true
}
```
<details>
  <summary>(Click to expand) features.requestUri options details</summary>
  <br>


#### requireUriRegistration

makes request_uri pre-registration mandatory/optional  


_**default value**_:
```js
true
```

</details>

### features.resourceIndicators

[draft-ietf-oauth-resource-indicators-02](https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-02) - Resource Indicators for OAuth 2.0  

Enables the use of `resource` parameter for the authorization and token endpoints. In order for the feature to be any useful you must also use the `audiences` helper function to validate the resource(s) and transform it to jwt's token audience.   
  


_**default value**_:
```js
{
  enabled: false
}
```
<details>
  <summary>(Click to expand) Example use</summary>
  <br>


This example will
 - throw based on an OP policy when unrecognized or unauthorized resources are requested
 - transform resources to audience and push them down to the audience of access tokens
 - take both, the parameter and previously granted resources into consideration
  

```js
// const { InvalidTarget } = Provider.errors;
// `resourceAllowedForClient` is the custom OP policy
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
      const allowed = await resourceAllowedForClient(resourceParam, grantedResource, client);
      if (!allowed) {
        throw new InvalidResource('unauthorized "resource" requested');
      }
      // => array of validated and transformed string audiences or undefined if no audiences
      //    are to be listed
      return transform(resourceParam, grantedResource);
    }
  },
  formats: {
    default: 'opaque',
    AccessToken(ctx, token) {
      if (Array.isArray(token.aud)) {
        return 'jwt';
      }
      return 'opaque';
    }
  },
  // ...
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

### features.sessionManagement

[Session Management 1.0 - draft 28](https://openid.net/specs/openid-connect-session-1_0-28.html)  

Enables Session Management features.  


_**default value**_:
```js
{
  enabled: false,
  keepHeaders: false
}
```
<details>
  <summary>(Click to expand) features.sessionManagement options details</summary>
  <br>


#### keepHeaders

Enables/Disables removing frame-ancestors from Content-Security-Policy and X-Frame-Options headers.  

_**recommendation**_: Only enable this if you know what you're doing either in a followup middleware or your app server, otherwise you shouldn't have the need to touch this option.  

_**default value**_:
```js
false
```

</details>

### features.webMessageResponseMode

[draft-sakimura-oauth-wmrm-00](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00) - OAuth 2.0 Web Message Response Mode  

Enables `web_message` response mode.   
 Note: Although a general advise to use a `helmet` ([express](https://www.npmjs.com/package/helmet), [koa](https://www.npmjs.com/package/koa-helmet)) it is especially advised for your interaction views routes if Web Message Response Mode is available on your deployment.  


_**default value**_:
```js
{
  enabled: false
}
```

### acrValues

Array of strings, the Authentication Context Class References that OP supports.  


_**default value**_:
```js
[]
```

### audiences

Helper used by the OP to push additional audiences to issued Access and ClientCredentials Tokens. The return value should either be falsy to omit adding additional audiences or an array of strings to push.  


_**default value**_:
```js
async audiences(ctx, sub, token, use) {
  // @param ctx   - koa request context
  // @param sub   - account identifier (subject)
  // @param token - the token to which these additional audiences will be passed to
  // @param use   - can be one of "access_token" or "client_credentials"
  //   depending on where the specific audiences are intended to be put in
  return undefined;
}
```

### claims

Array of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.  


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

### clientBasedCORS

Helper function used to check whether a given CORS request should be allowed based on the request's client.  


_**default value**_:
```js
clientBasedCORS(ctx, origin, client) {
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
<details>
  <summary>(Click to expand) Changing the default client token_endpoint_auth_method</summary>
  <br>


To change the default client token_endpoint_auth_method configure `clientDefaults` to be an object like so:
  

```js
{
  token_endpoint_auth_method: 'client_secret_post'
}
```
</details>
<details>
  <summary>(Click to expand) Changing the default client response type to `code id_token`</summary>
  <br>


To change the default client response_types configure `clientDefaults` to be an object like so:
  

```js
{
  response_types: ['code id_token'],
  grant_types: ['authorization_code', 'implicit'],
}
```
</details>

### clockTolerance

A `Number` value (in seconds) describing the allowed system clock skew for validating client-provided JWTs, e.g. Request objects and otherwise comparing timestamps  

_**recommendation**_: Only set this to a reasonable value when needed to cover server-side client and oidc-provider server clock skew. More than 5 minutes (if needed) is probably a sign something else is wrong.  

_**default value**_:
```js
0
```

### conformIdTokenClaims

ID Token only contains End-User claims when the requested `response_type` is `id_token`  

[Core 1.0 - 5.4. Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.4) defines that claims requested using the `scope` parameter are only returned from the UserInfo Endpoint unless the `response_type` is `id_token`. This is the default oidc-provider behaviour, you can turn this behaviour off and return End-User claims with all ID Tokens by providing this configuration as `false`.   
  


_**default value**_:
```js
true
```

### cookies

Options for the [cookie module](https://github.com/pillarjs/cookies#cookiesset-name--value---options--) used by the OP to keep track of various User-Agent states.  


### cookies.keys

[Keygrip][keygrip-module] Signing keys used for cookie signing to prevent tampering.  

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

Cookie names used by the OP to store and transfer various states.  


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
<details>
  <summary>(Click to expand) To enable a dynamic scope values like `api:write:{hex id}` and `api:read:{hex id}`</summary>
  <br>


Configure `dynamicScopes` like so:
  

```js
[
  /^api:write:[a-fA-F0-9]{2,}$/,
  /^api:read:[a-fA-F0-9]{2,}$/,
]
```
</details>

### expiresWithSession

Helper used by the OP to decide whether the given authorization code/ device code or implicit returned access token be bound to the user session. This will be applied to all tokens issued from the authorization / device code in the future. When tokens are session-bound the session will be loaded by its `uid` every time the token is encountered. Session bound tokens will effectively get revoked if the end-user logs out.  


_**default value**_:
```js
async expiresWithSession(ctx, token) {
  return !token.scopes.has('offline_access');
}
```

### extraClientMetadata

Allows for custom client metadata to be defined, validated, manipulated as well as for existing property validations to be extended  


### extraClientMetadata.properties

Array of property names that clients will be allowed to have defined. Property names will have to strictly follow the ones defined here. However, on a Client instance property names will be snakeCased.  


_**default value**_:
```js
[]
```

### extraClientMetadata.validator

validator function that will be executed in order once for every property defined in `extraClientMetadata.properties`, regardless of its value or presence on the client metadata passed in. Must be synchronous, async validators or functions returning Promise will be rejected during runtime. To modify the current client metadata values (for current key or any other) just modify the passed in `metadata` argument.   
  


_**default value**_:
```js
validator(key, value, metadata) {
  // validations for key, value, other related metadata
  // throw new Provider.errors.InvalidClientMetadata() to reject the client metadata (see all
  //   errors on Provider.errors)
  // metadata[key] = value; to assign values
  // return not necessary, metadata is already a reference.
}
```
<details>
  <summary>(Click to expand) Using extraClientMetadata to allow software_statement dynamic client registration property
</summary>
  <br>

```js
const { verify } = require('jsonwebtoken');
const {
  errors: { InvalidSoftwareStatement, UnapprovedSoftwareStatement },
} = require('oidc-provider');
const softwareStatementKey = require('path/to/public/key');
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
            algorithms: ['RS256'],
            issuer: 'Software Statement Issuer',
          });
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

This option allows to configure the token storage and value formats. The different values change how a client-facing token value is generated as well as what properties get sent to the adapter for storage.
 - `opaque` (default) formatted tokens store every property as a root property in your adapter
 - `jwt` formatted tokens are issued as JWTs and stored the same as `opaque` only with additional property `jwt`. The signing algorithm for these tokens uses the client's `id_token_signed_response_alg` value and falls back to `RS256` for tokens with no relation to a client or when the client's alg is `none`
 - the value may also be a function dynamically determining the format (returning either `jwt` or `opaque` depending on the token itself)   
  


_**default value**_:
```js
{
  AccessToken: undefined,
  ClientCredentials: undefined,
  extraJwtAccessTokenClaims: [AsyncFunction: extraJwtAccessTokenClaims]
}
```
<details>
  <summary>(Click to expand) To enable JWT Access Tokens</summary>
  <br>


Configure `formats`:
  

```js
{ AccessToken: 'jwt' }
```
</details>
<details>
  <summary>(Click to expand) To dynamically decide on the format used, e.g. only if it is intended for more audiences</summary>
  <br>


Configure `formats`:
  

```js
{
  AccessToken(ctx, token) {
    if (Array.isArray(token.aud)) {
      return 'jwt';
    }
    return 'opaque';
  }
}
```
</details>

### formats.extraJwtAccessTokenClaims

helper function used by the OP to get additional JWT formatted token claims when it is being created  


_**default value**_:
```js
async extraJwtAccessTokenClaims(ctx, token) {
  return undefined;
}
```
<details>
  <summary>(Click to expand) To push additional claims to a JWT format Access Token
</summary>
  <br>

```js
{
  formats: {
    AccessToken: 'jwt',
    async extraJwtAccessTokenClaims(ctx, token) {
      return {
        preferred_username: 'johnny',
      };
    }
  }
}
```
</details>

### httpOptions

Helper called whenever the provider calls an external HTTP(S) resource. Use to change the [got](https://github.com/sindresorhus/got/tree/v9.6.0) library's request options as they happen. This can be used to e.g. Change the request timeout option or to configure the global agent to use HTTP_PROXY and HTTPS_PROXY environment variables.   
  


_**default value**_:
```js
httpOptions(options) {
  options.followRedirect = false;
  options.headers['User-Agent'] = 'oidc-provider/${VERSION} (${ISSUER_IDENTIFIER})';
  options.retry = 0;
  options.throwHttpErrors = false;
  options.timeout = 2500;
  return options;
}
```
<details>
  <summary>(Click to expand) To change the request's timeout</summary>
  <br>


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

### interactionUrl

Helper used by the OP to determine where to redirect User-Agent for necessary interaction, can return both absolute and relative urls  


_**default value**_:
```js
async interactionUrl(ctx, interaction) {
  return `/interaction/${ctx.oidc.uid}`;
}
```

### interactions

structure of Prompts and their checks formed by Prompt and Check class instances. The default you can modify and the classes are available under `Provider.interaction`.   
  


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

          if (oidc.session.past(oidc.params.max_age)) {
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
          const hint = oidc.params.id_token_hint;
          if (hint === undefined) {
            return false;
          }

          let payload;
          try {
            ({ payload } = await oidc.provider.IdToken.validate(hint, oidc.client));
          } catch (err) {
            throw new errors.InvalidRequest(`could not validate id_token_hint (${err.message})`);
          }

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
<details>
  <summary>(Click to expand) configuring prompts
</summary>
  <br>

```js
const { interaction: { Prompt, Check, DEFAULT } } = require('oidc-provider');
// DEFAULT.get(name) => returns a Prompt instance by its name
// DEFAULT.remove(name) => removes a Prompt instance by its name
// DEFAULT.add(prompt, index) => adds a Prompt instance to a specific index, default is to last index
// prompt.checks.get(reason) => returns a Check instance by its reason
// prompt.checks.remove(reason) => removes a Check instance by its reason
// prompt.checks.add(check, index) => adds a Check instance to a specific index, default is to last index
```
</details>

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

Helper used by the OP to decide whether a refresh token will be issued or not   
  


_**default value**_:
```js
async issueRefreshToken(ctx, client, code) {
  return client.grantTypes.includes('refresh_token') && code.scopes.has('offline_access');
}
```
<details>
  <summary>(Click to expand) To always issue a refresh tokens ...</summary>
  <br>


... If a client has the grant whitelisted and scope includes offline_access or the client is a public web client doing code flow. Configure `issueRefreshToken` like so
  

```js
async issueRefreshToken(ctx, client, code) {
  if (!client.grantTypes.includes('refresh_token')) {
    return false;
  }
  return code.scopes.has('offline_access') || (client.applicationType === 'web' && client.tokenEndpointAuthMethod === 'none');
}
```
</details>

### logoutSource

HTML source rendered when session management feature renders a confirmation prompt for the User-Agent.  


_**default value**_:
```js
async logoutSource(ctx, form) {
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

### pairwiseIdentifier

Function used by the OP when resolving pairwise ID Token and Userinfo sub claim values. See [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.8.1)  

_**recommendation**_: Since this might be called several times in one request with the same arguments consider using memoization or otherwise caching the result based on account and client ids.  

_**default value**_:
```js
async pairwiseIdentifier(ctx, accountId, client) {
  return crypto.createHash('sha256')
    .update(client.sectorIdentifier)
    .update(accountId)
    .update(os.hostname()) // put your own unique salt here, or implement other mechanism
    .digest('hex');
}
```

### pkceMethods

fine-tune the supported code challenge methods. Supported values are
 - `S256`
 - `plain`  


_**default value**_:
```js
[
  'S256'
]
```

### postLogoutSuccessSource

HTML source rendered when session management feature concludes a logout but there was no `post_logout_redirect_uri` provided by the client.  


_**default value**_:
```js
async postLogoutSuccessSource(ctx) {
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

### renderError

Helper used by the OP to present errors to the User-Agent  


_**default value**_:
```js
async renderError(ctx, out, error) {
  ctx.type = 'html';
  ctx.body = `<!DOCTYPE html>
<head>
<title>oops! something went wrong</title>
<style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
</head>
<body>
<div>
  <h1>oops! something went wrong</h1>
  ${Object.entries(out).map(([key, value]) => `<pre><strong>${key}</strong>: ${value}</pre>`).join('')}
</div>
</body>
</html>`;
}
```

### responseTypes

Array of response_type values that OP supports   
  


_**default value**_:
```js
[
  'code id_token token',
  'code id_token',
  'code token',
  'code',
  'id_token token',
  'id_token',
  'none'
]
```
<details>
  <summary>(Click to expand) Supported values list</summary>
  <br>


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
 - otherwise always rotate public client tokens
 - otherwise only rotate tokens if they're being used close to their expiration (>= 70% TTL passed)  


_**default value**_:
```js
rotateRefreshToken(ctx) {
  const { RefreshToken: refreshToken, Client: client } = ctx.oidc.entities;
  // cap the maximum amount of time a refresh token can be
  // rotated for up to 1 year, afterwards its TTL is final
  if (refreshToken.totalLifetime() >= 365.25 * 24 * 60 * 60) {
    return false;
  }
  // rotate public client refresh tokens
  if (client.tokenEndpointAuthMethod === 'none') {
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
  certificates: '/certs',
  check_session: '/session/check',
  code_verification: '/device',
  device_authorization: '/device/auth',
  end_session: '/session/end',
  introspection: '/token/introspection',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'none',
  'client_secret_basic', 'client_secret_post',
  'client_secret_jwt', 'private_key_jwt',
  'tls_client_auth', 'self_signed_tls_client_auth',
]
```
</details>
<details>
  <summary>(Click to expand) Setting up the environment for tls_client_auth and self_signed_tls_client_auth</summary>
  <br>


To enable mutual TLS based authentication methods the provider expects your TLS-offloading proxy to handle the client certificate validation, parsing, handling, etc. Once set up you are expected to forward `x-ssl-client-verify`, `x-ssl-client-s-dn` and `x-ssl-client-cert` headers with variable values set by this proxy. An important aspect is to sanitize the inbound request headers at the proxy. <br/><br/> The most common openssl based proxies are Apache and NGINX, with those you're looking to use <br/><br/> __`SSLVerifyClient` (Apache) / `ssl_verify_client` (NGINX)__ with the appropriate configuration value that matches your setup requirements. <br/><br/> __`SSLCACertificateFile` or `SSLCACertificatePath` (Apache) / `ssl_client_certificate` (NGINX)__ with the values pointing to your accepted CA Certificates. <br/><br/> Set the proxy request headers with variables set as a result of enabling mutual TLS
  

```nginx
# NGINX
proxy_set_header x-ssl-client-cert $ssl_client_cert;
proxy_set_header x-ssl-client-verify $ssl_client_verify;
proxy_set_header x-ssl-client-s-dn $ssl_client_s_dn;
```
```apache
# Apache
RequestHeader set x-ssl-client-cert ""
RequestHeader set x-ssl-client-cert "%{SSL_CLIENT_CERT}s"
RequestHeader set x-ssl-client-verify ""
RequestHeader set x-ssl-client-verify "%{SSL_CLIENT_VERIFY}s"
RequestHeader set x-ssl-client-s-dn ""
RequestHeader set x-ssl-client-s-dn "%{SSL_CLIENT_S_DN}s"
```
You should also consider hosting the endpoints supporting client authentication, on a separate host name or port in order to prevent unintended impact on the TLS behaviour of your other endpoints, e.g. Discovery or the authorization endpoint, by updating the discovery response to add [draft-ietf-oauth-mtls-14](https://tools.ietf.org/html/draft-ietf-oauth-mtls-14) specified `mtls_endpoint_aliases`.
  

```js
provider.use(async (ctx, next) => {
  await next();
  if (ctx.oidc.route === 'discovery') {
    ctx.body.mtls_endpoint_aliases = {};
    const endpointAuthMethodKeys = [
      'token_endpoint_auth_methods_supported',
      'introspection_endpoint_auth_methods_supported',
      'revocation_endpoint_auth_methods_supported',
    ];
    // splits `*_endpoint_auth_methods_supported` into two namespaces (mutual-TLS and regular);
    endpointAuthMethodKeys.forEach((key) => {
      if (ctx.body[key]) {
        ctx.body.mtls_endpoint_aliases[key] = ctx.body[key].filter(k => k.endsWith('tls_client_auth'));
        ctx.body[key] = ctx.body[key].filter(k => !ctx.body.mtls_endpoint_aliases[key].includes(k));
      }
    });
    const mtlsEndpoints = [
      'userinfo_endpoint',
      'token_endpoint',
      'introspection_endpoint',
      'revocation_endpoint',
      'device_authorization_endpoint',
    ];
    // aliases endpoints accepting client certificates in `mtls_endpoint_aliases`
    const mtlsOrigin = 'https://mtls.op.example.com';
    mtlsEndpoints.forEach((key) => {
      if (ctx.body[key]) {
        ctx.body.mtls_endpoint_aliases[key] = `${mtlsOrigin}${url.parse(ctx.body[key]).pathname}`;
      }
    });
  }
});
```
When doing that be sure to remove the client provided headers of the same name on the non-mutual TLS enabled host name / port in your proxy setup or block the routes for these there completely.  


</details>

### ttl

Expirations (in seconds, or dynamically returned value) for all token types   
  

_**recommendation**_: Do not set token TTLs longer then they absolutely have to be, the shorter the TTL, the better. Rather than setting crazy high Refresh Token TTL look into `rotateRefreshToken` configuration option which is set up in way that when refresh tokens are regularly used they will have their TTL refreshed (via rotation). This is inline with the [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-12)  

_**default value**_:
```js
{
  AccessToken: 3600,
  AuthorizationCode: 600,
  ClientCredentials: 600,
  DeviceCode: 600,
  IdToken: 3600,
  RefreshToken: 1209600
}
```
<details>
  <summary>(Click to expand) To resolve a ttl on runtime for each new token</summary>
  <br>


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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES
  'A128KW', 'A192KW', 'A256KW',
  // symmetric AES GCM based
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES
  'A128KW', 'A192KW', 'A256KW',
  // symmetric AES GCM based
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES
  'A128KW', 'A192KW', 'A256KW',
  // symmetric AES GCM based
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES
  'A128KW', 'A192KW', 'A256KW',
  // symmetric AES GCM based
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA1_5',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES
  'A128KW', 'A192KW', 'A256KW',
  // symmetric AES GCM based
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // symmetric PBES2 + AES
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

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
<details>
  <summary>(Click to expand) Supported values list
</summary>
  <br>

```js
[
  'none',
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
]
```
</details>
<!-- END CONF OPTIONS -->

[got-library]: https://github.com/sindresorhus/got
[token-exchange]: https://tools.ietf.org/html/draft-ietf-oauth-token-exchange
[defaults]: /lib/helpers/defaults.js
[keygrip-module]: https://www.npmjs.com/package/keygrip
[support-patreon]: https://www.patreon.com/panva
[support-paypal]: https://www.paypal.me/panva
[sponsor-auth0]: https://auth0.com/overview?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=oidc-provider&utm_content=auth
