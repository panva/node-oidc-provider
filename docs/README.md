# oidc-provider API documentation

This module provides an OAuth 2.0 Authorization Server implementation with support for OpenID Connect and
additional features conforming to current security best practices and emerging standards.

The authorization server is designed to be extended and configured in various ways to accommodate a wide variety of
deployment scenarios and use cases. Implementation requires configuring the authorization server instance with account
discovery methods, persistent data storage, and end-user interaction handlers. The [example](/example) application
serves as an excellent starting point to understand the required implementation components.

## Sponsor

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/panva/node-oidc-provider/HEAD/sponsor/Auth0byOkta_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/panva/node-oidc-provider/HEAD/sponsor/Auth0byOkta_light.png">
  <img height="65" align="left" alt="Auth0 by Okta" src="https://raw.githubusercontent.com/panva/node-oidc-provider/HEAD/sponsor/Auth0byOkta_light.png">
</picture>

If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan. [Create an Auth0 account; it's free!][sponsor-auth0]<br><br>

## Support

If you or your company use this module, or you need help using/upgrading the module, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree. The only way to guarantee you get feedback from the author & sole maintainer of this module is to support the package through GitHub Sponsors.

<br>

---

**Table of Contents**

- [Basic configuration example](#basic-configuration-example)
- [Accounts](#accounts)
- [User flows](#user-flows)
- [Custom Grant Types ❗](#custom-grant-types)
- [General access to `ctx` ❗](#general-access-to-ctx)
- [Registering module middlewares (helmet, ip-filters, rate-limiters, etc)](#registering-module-middlewares-helmet-ip-filters-rate-limiters-etc)
- [Pre- and post-middlewares ❗](#pre--and-post-middlewares)
- [Mounting oidc-provider](#mounting-oidc-provider)
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
import * as oidc from "oidc-provider";

const provider = new oidc.Provider("http://localhost:3000", {
  // refer to the documentation for other available configuration
  clients: [
    {
      client_id: "foo",
      client_secret: "bar",
      redirect_uris: ["http://localhost:8080/cb"],
      // ... other client properties
    },
  ],
});

const server = provider.listen(3000, () => {
  console.log(
    "oidc-provider listening on port 3000, check http://localhost:3000/.well-known/openid-configuration",
  );
});
```

External type definitions are available via [DefinitelyTyped](https://npmjs.com/package/@types/oidc-provider).

## Accounts

The authorization server MUST be able to locate an account and once found the account object MUST contain an
`accountId` property as well as a `claims()` function returning an object with claims that correspond to the claims
the authorization server supports. The provider MUST be configured with an account discovery method by implementing
the `findAccount` function. The `claims()` function MAY return a Promise that is later resolved or rejected.

```js
import * as oidc from "oidc-provider";

const provider = new oidc.Provider("http://localhost:3000", {
  async findAccount(ctx, id) {
    return {
      accountId: id,
      async claims(use, scope) {
        return { sub: id };
      },
    };
  },
});
```

## User flows

Since oidc-provider only comes with feature-less views and interaction handlers, implementations MUST provide these
components. The following describes how this module allows such customization:

When oidc-provider cannot fulfill the authorization request for any of the possible reasons (missing
user session, requested ACR not fulfilled, prompt requested, ...) it will resolve the
[`interactions.url`](#interactionsurl) helper function and redirect the User-Agent to that URL. Before
doing so it will save a short-lived "interaction session" and dump its identifier into a cookie scoped to the
resolved interaction path.

This interaction session contains:

- details of the interaction that is required
- all authorization request parameters
- current end-user session account ID should there be one
- the URL to redirect the user to once interaction is finished

The authorization server expects that implementations resolve the prompt interaction and then redirect the User-Agent
back with the results.

Once the required interactions are finished the implementation is expected to redirect back to the authorization
endpoint, affixed by the uid of the interaction session and the interaction results stored in the
interaction session object.

The authorization server instance comes with helpers that aid with getting interaction details as well as
packing the results. See them used in the [in-repo](/example) examples.

**`provider.interactionDetails(req, res)`**

```js
// with express
expressApp.get("/interaction/:uid", async (req, res) => {
  const details = await provider.interactionDetails(req, res);
  // ...
});

// with koa
router.get("/interaction/:uid", async (ctx, next) => {
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  // ...
});
```

**`provider.interactionFinished(req, res, result)`**

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
    accountId: string, // logged-in account id
    acr: string, // acr value for the authentication
    amr: string[], // amr values for the authentication
    remember: boolean, // true if authorization server should use a persistent cookie rather than a session one, defaults to true
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

**`provider.interactionResult`**
Unlike `provider.interactionFinished` authorization request resume uri is returned instead of
immediate http redirect.

```js
// with express
expressApp.post("/interaction/:uid/login", async (req, res) => {
  const redirectTo = await provider.interactionResult(req, res, result);

  res.send({ redirectTo });
});

// with koa
router.post("/interaction/:uid", async (ctx, next) => {
  const redirectTo = await provider.interactionResult(ctx.req, ctx.res, result);

  ctx.body = { redirectTo };
});
```

## Custom Grant Types

The authorization server comes with the basic grants implemented, but implementations may register custom grant types,
for example to implement an
[OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html). Implementations can examine the standard
grant factories [here](/lib/actions/grants).

```js
const parameters = [
  "audience",
  "resource",
  "scope",
  "requested_token_type",
  "subject_token",
  "subject_token_type",
  "actor_token",
  "actor_token_type",
];
const allowedDuplicateParameters = ["audience", "resource"];
const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";

async function tokenExchangeHandler(ctx, next) {
  // ctx.oidc.params holds the parsed parameters
  // ctx.oidc.client has the authenticated client
  // your grant implementation
  // see /lib/actions/grants for references on how to instantiate and issue tokens
}

provider.registerGrantType(grantType, tokenExchangeHandler, parameters, allowedDuplicateParameters);
```

## General access to `ctx`

It is possible to access the `ctx` object in functions and helpers that don't get it as an argument via the
Provider static `ctx` getter (`Provider.ctx`). This utilizes node's 
[`AsyncLocalStorage`](https://nodejs.org/api/async_context.html#class-asynclocalstorage) and results in `ctx`
being available in method invocations where it isn't normally passed as an argument (e.g. in [Adapter](#adapter))
so long as that method is invoked within the context of an HTTP request that is being handled by oidc-provider's
route handlers.

## Registering module middlewares (helmet, ip-filters, rate-limiters, etc)

When using `provider` or `provider.callback()` as a mounted application in your own koa or express
stack just follow the respective module's documentation. When using the `provider` Koa
instance directly this is effectively the same as [registering any Koa middleware](https://koajs.com/#app-use-function-).

```js
import helmet from "koa-helmet";

provider.use(helmet());
```

## Pre- and post-middlewares

You can push custom middleware to be executed before and after oidc-provider's route handlers. This is effectively
the same as [Middleware Cascading in Koa](https://koajs.com/#cascading).

```js
provider.use(async (ctx, next) => {
  /** pre-processing
   * you may target a specific action here by matching `ctx.path`
   */
  console.log("pre middleware", ctx.method, ctx.path);

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
  console.log("post middleware", ctx.method, ctx.oidc.route);
});
```

## Mounting oidc-provider

The following snippets show how a Provider instance can be mounted to existing applications with a
path prefix `/oidc`.

> [!NOTE]
> If you mount oidc-provider to a path it's likely you will have to also update the
> [`interactions.url`](#interactionsurl) configuration to reflect the new path.

> [!NOTE]
> Depending on the value of the issuer identifier you shall make sure that the expected
> authorization server metadata endpoints are available on the expected route

> [!TIP]
> Example: When the issuer identifier is `https://op.example.com/oidc` and you're mounting the
> provider routes to `/oidc` the following routes must be configured on the mounted-to
> application to be internally resolved to the respective provider routes.
>
> - `https://op.example.com/oidc/.well-known/openid-configuration`
> - `https://op.example.com/.well-known/oauth-authorization-server/oidc`

> [!TIP]
> Example: When the issuer identifier is `https://op.example.com` but you're mounting the
> provider routes to `/oidc` the following routes must be configured on the mounted-to
> application to be internally resolved to the respective provider routes.
>
> - `https://op.example.com/.well-known/openid-configuration`
> - `https://op.example.com/.well-known/oauth-authorization-server`

### to a `fastify` application

```js
// assumes fastify ^4.0.0
const fastify = new Fastify();
await fastify.register(require("@fastify/middie"));
// or
// await app.register(require('@fastify/express'));
fastify.use("/oidc", provider.callback());
```

### to a `hapi` application

```js
// assumes @hapi/hapi ^21.0.0
const callback = provider.callback();
hapiApp.route({
  path: `/oidc/{any*}`,
  method: "*",
  config: { payload: { output: "stream", parse: false } },
  async handler({ raw: { req, res } }, h) {
    req.originalUrl = req.url;
    req.url = req.url.replace("/oidc", "");

    callback(req, res);
    await once(res, "finish");

    req.url = req.url.replace("/", "/oidc");
    delete req.originalUrl;

    return res.writableEnded ? h.abandon : h.continue;
  },
});
```

### to a `nest` application

```ts
// assumes NestJS ^7.0.0
import { Controller, All, Req, Res } from "@nestjs/common";
import { Request, Response } from "express";
const callback = provider.callback();
@Controller("oidc")
export class OidcController {
  @All("/*")
  public mountedOidc(@Req() req: Request, @Res() res: Response): void {
    req.url = req.originalUrl.replace("/oidc", "");
    return callback(req, res);
  }
}
```

### to an `express` application

```js
// assumes express ^4.0.0 || ^5.0.0
expressApp.use("/oidc", provider.callback());
```

### to a `koa` application

```js
// assumes koa ^2.0.0 || ^3.0.0
// assumes koa-mount ^4.0.0
import mount from "koa-mount";
koaApp.use(mount("/oidc", provider));
```

## Trusting TLS offloading proxies

Having a TLS offloading proxy in front of Node.js running oidc-provider is
the norm. To let your downstream application know of the original protocol and
ip you have to tell your app to trust `x-forwarded-proto` and `x-forwarded-for`
headers commonly set by those proxies (as with any express/koa application).
This is needed for the authorization server responses to be correct (e.g. to have the right
https URL endpoints and keeping the right (secure) protocol).

Depending on your setup you should do the following in your downstream
application code

| setup                                             | example                   |
| ------------------------------------------------- | ------------------------- |
| standalone oidc-provider                          | `provider.proxy = true`   |
| oidc-provider mounted to an `express` application | `provider.proxy = true`   |
| oidc-provider mounted to a `koa` application      | `yourKoaApp.proxy = true` |
| oidc-provider mounted to a `fastify` application  | `provider.proxy = true`   |
| oidc-provider mounted to a `hapi` application     | `provider.proxy = true`   |
| oidc-provider mounted to a `nest` application     | `provider.proxy = true`   |

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
  - [rpInitiatedLogout](#featuresrpinitiatedlogout)
  - [userinfo](#featuresuserinfo)
  - Experimental features:
    - [attestClientAuth](#featuresattestclientauth)
    - [externalSigningSupport (e.g. KMS)](#featuresexternalsigningsupport)
    - [richAuthorizationRequests](#featuresrichauthorizationrequests)
    - [rpMetadataChoices](#featuresrpmetadatachoices)
    - [webMessageResponseMode](#featureswebmessageresponsemode)
- [acrValues](#acrvalues)
- [allowOmittingSingleRegisteredRedirectUri](#allowomittingsingleregisteredredirecturi)
- [assertJwtClientAuthClaimsAndHeader](#assertjwtclientauthclaimsandheader)
- [claims ❗](#claims)
- [clientBasedCORS ❗](#clientbasedcors)
- [clientDefaults](#clientdefaults)
- [clockTolerance](#clocktolerance)
- [conformIdTokenClaims](#conformidtokenclaims)
- [cookies](#cookies)
- [discovery](#discovery)
- [enableHttpPostMethods](#enablehttppostmethods)
- [expiresWithSession](#expireswithsession)
- [extraClientMetadata](#extraclientmetadata)
- [extraParams](#extraparams)
- [extraTokenClaims](#extratokenclaims)
- [fetch](#fetch)
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
- [clientAuthMethods](#clientauthmethods)
- [ttl ❗](#ttl)
- [enabledJWA](#enabledjwa)

<!-- DO NOT EDIT, COMMIT OR STAGE CHANGES BELOW THIS LINE -->
<!-- START CONF OPTIONS -->
### adapter

Specifies the storage adapter implementation for persisting authorization server state. The default implementation provides a basic in-memory adapter suitable for development and testing purposes only. When this process is restarted, all stored information will be lost. Production deployments MUST provide a custom adapter implementation that persists data to external storage (e.g., database, Redis, etc.).   
 The adapter constructor will be instantiated for each model type when first accessed.   
  

See:
- [The expected interface](/example/my_adapter.js)
- [Example MongoDB adapter implementation](https://github.com/panva/node-oidc-provider/discussions/1308)
- [Example Redis adapter implementation](https://github.com/panva/node-oidc-provider/discussions/1309)
- [Example Redis w/ JSON Adapter](https://github.com/panva/node-oidc-provider/discussions/1310)
- [Default in-memory adapter implementation](/lib/adapters/memory_adapter.js)
- [Community Contributed Adapter Archive](https://github.com/panva/node-oidc-provider/discussions/1311)

---

### clients

An array of client metadata objects representing statically configured OAuth 2.0 and OpenID Connect clients. These clients are persistent, do not expire, and remain available throughout the authorization server's lifetime. For dynamic client discovery, the authorization server will invoke the adapter's `find` method when encountering unregistered client identifiers.   
 To restrict the authorization server to only statically configured clients and disable dynamic registration, configure the adapter to return falsy values for client lookup operations (e.g., `return Promise.resolve()`).   
 Each client's metadata shall be validated according to the specifications in which the respective properties are defined.   
  


_**default value**_:
```js
[]
```
<a id="clients-available-metadata"></a><details><summary>Example: (Click to expand) Available Metadata.</summary><br>


application_type, client_id, client_name, client_secret, client_uri, contacts, default_acr_values, default_max_age, grant_types, id_token_signed_response_alg, initiate_login_uri, jwks, jwks_uri, logo_uri, policy_uri, post_logout_redirect_uris, redirect_uris, require_auth_time, response_types, response_modes, scope, sector_identifier_uri, subject_type, token_endpoint_auth_method, tos_uri, userinfo_signed_response_alg <br/><br/>The following metadata is available but may not be recognized depending on this authorization server's configuration.<br/><br/> authorization_encrypted_response_alg, authorization_encrypted_response_enc, authorization_signed_response_alg, backchannel_logout_session_required, backchannel_logout_uri, id_token_encrypted_response_alg, id_token_encrypted_response_enc, introspection_encrypted_response_alg, introspection_encrypted_response_enc, introspection_signed_response_alg, request_object_encryption_alg, request_object_encryption_enc, request_object_signing_alg, tls_client_auth_san_dns, tls_client_auth_san_email, tls_client_auth_san_ip, tls_client_auth_san_uri, tls_client_auth_subject_dn, tls_client_certificate_bound_access_tokens, use_mtls_endpoint_aliases, token_endpoint_auth_signing_alg, userinfo_encrypted_response_alg, userinfo_encrypted_response_enc  


</details>

---

### findAccount

Specifies a function that shall be invoked to load an account and retrieve its available claims during authorization server operations. This function enables the authorization server to resolve end-user account information based on the provided account identifier. The function MUST return a Promise that resolves to an account object containing an `accountId` property and a `claims()` method that returns an object with claims corresponding to the claims supported by the issuer. The `claims()` method may also return a Promise that shall be resolved or rejected according to account availability and authorization server policy.  


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

---

### jwks

Specifies the JSON Web Key Set that shall be used by the authorization server for cryptographic signing and decryption operations. The key set MUST be provided in [JWK Set format](https://www.rfc-editor.org/rfc/rfc7517.html#section-5) as defined in RFC 7517. All keys within the set MUST be private keys.   
 Supported key types include:   
 - RSA
 - OKP (Ed25519 and X25519 sub types)
 - EC (P-256, P-384, and P-521 curves)   
  

_**recommendation**_: Be sure to follow best practices for distributing private keying material and secrets for your respective target deployment environment.  

_**recommendation**_: The following action order is recommended when rotating signing keys on a distributed deployment with rolling reloads in place.
 1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become available for verification should they be encountered but not yet used for signing
 2. reload all your processes
 3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be used for signing after reload
 4. reload all your processes  


---

### features

Specifies the authorization server feature capabilities that shall be enabled or disabled. This configuration controls the availability of optional OAuth 2.0 and OpenID Connect extensions, experimental specifications, and proprietary enhancements.   
 Certain features may be designated as experimental implementations. When experimental features are enabled, the authorization server will emit warnings to indicate that breaking changes may occur in future releases. These changes will be published as minor version updates of the oidc-provider module.   
 To suppress experimental feature warnings and ensure configuration validation against breaking changes, implementations shall acknowledge the specific experimental feature version using the acknowledgment mechanism demonstrated in the example below. When an unacknowledged breaking change is detected, the authorization server configuration will throw an error during instantiation.   
  

<a id="features-acknowledging-an-experimental-feature"></a><details><summary>Example: (Click to expand) Acknowledging an experimental feature.</summary><br>

```js
import * as oidc from 'oidc-provider'
new oidc.Provider('http://localhost:3000', {
  features: {
    webMessageResponseMode: {
      enabled: true,
    },
  },
});
// The above code produces this NOTICE
// NOTICE: The following experimental features are enabled and their implemented version not acknowledged
// NOTICE:   - OAuth 2.0 Web Message Response Mode - draft 01 (Acknowledging this feature's implemented version can be done with the value 'individual-draft-01')
// NOTICE: Breaking changes between experimental feature updates may occur and these will be published as MINOR semver oidc-provider updates.
// NOTICE: You may disable this notice and be warned when breaking updates occur by acknowledging the current experiment's version. See the documentation for more details.
new oidc.Provider('http://localhost:3000', {
  features: {
    webMessageResponseMode: {
      enabled: true,
      ack: 'individual-draft-01',
    },
  },
});
// No more NOTICE, at this point if the experimental was updated and contained no breaking
// changes, you're good to go, still no NOTICE, your code is safe to run.
// Now lets assume you upgrade oidc-provider version and it includes a breaking change in
// this experimental feature
new oidc.Provider('http://localhost:3000', {
  features: {
    webMessageResponseMode: {
      enabled: true,
      ack: 'individual-draft-01',
    },
  },
});
// Thrown:
// Error: An unacknowledged version of an experimental feature is included in this oidc-provider version.
```
</details>

---

### features.attestClientAuth

[`draft-ietf-oauth-attestation-based-client-auth-06`](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-06.html) - OAuth 2.0 Attestation-Based Client Authentication  

> [!NOTE]
> This is an experimental feature.

Specifies whether Attestation-Based Client Authentication capabilities shall be enabled. When enabled, the authorization server shall support the `attest_jwt_client_auth` authentication method within the server's `clientAuthMethods` configuration. This mechanism enables Client Instances to authenticate using a Client Attestation JWT issued by a trusted Client Attester and a corresponding Client Attestation Proof-of-Possession JWT generated by the Client Instance.   
  


_**default value**_:
```js
{
  ack: undefined,
  assertAttestationJwtAndPop: [AsyncFunction: assertAttestationJwtAndPop], // see expanded details below
  challengeSecret: undefined,
  enabled: false,
  getAttestationSignaturePublicKey: [AsyncFunction: getAttestationSignaturePublicKey] // see expanded details below
}
```

<details><summary>(Click to expand) features.attestClientAuth options details</summary><br>


#### assertAttestationJwtAndPop

Specifies a helper function that shall be invoked to perform additional validation of the Client Attestation JWT and Client Attestation Proof-of-Possession JWT beyond the specification requirements. This enables enforcement of extension profiles, deployment-specific policies, or additional security constraints.   
 At the point of invocation, both JWTs have undergone signature verification and standard validity claim validation. The function may throw errors to reject non-compliant attestations or return successfully to indicate acceptance of the client authentication attempt.  


_**default value**_:
```js
async function assertAttestationJwtAndPop(ctx, attestation, pop, client) {
  // @param ctx - koa request context
  // @param attestation - verified and parsed Attestation JWT
  //        attestation.protectedHeader - parsed protected header object
  //        attestation.payload - parsed protected header object
  //        attestation.key - CryptoKey that verified the Attestation JWT signature
  // @param pop - verified and parsed Attestation JWT PoP
  //        pop.protectedHeader - parsed protected header object
  //        pop.payload - parsed protected header object
  //        pop.key - CryptoKey that verified the Attestation JWT PoP signature
  // @param client - client making the request
}
```

#### challengeSecret

Specifies the cryptographic secret value used for generating server-provided challenges. This value MUST be a 32-byte length Buffer instance to ensure sufficient entropy for secure challenge generation.  


_**default value**_:
```js
undefined
```

#### getAttestationSignaturePublicKey

Specifies a helper function that shall be invoked to verify the issuer identifier of a Client Attestation JWT and retrieve the public key used for signature verification. At the point of this function's invocation, only the JWT format has been validated; no cryptographic or claims verification has occurred.   
 The function MUST return a public key in one of the supported formats: CryptoKey, KeyObject, or JSON Web Key (JWK) representation. The authorization server shall use this key to verify the Client Attestation JWT signature.   
  


_**default value**_:
```js
async function getAttestationSignaturePublicKey(ctx, iss, header, client) {
  // @param ctx - koa request context
  // @param iss - Issuer Identifier from the Client Attestation JWT
  // @param header - Protected Header of the Client Attestation JWT
  // @param client - client making the request
  throw new Error('features.attestClientAuth.getAttestationSignaturePublicKey not implemented');
}
```
<a id="get-attestation-signature-public-key-fetching-attester-public-keys-from-the-attester's-hosted-jwks"></a><details><summary>Example: (Click to expand) Fetching attester public keys from the attester's hosted JWKS</summary><br>

```js
import * as jose from 'jose';
const attesters = new Map(Object.entries({
  'https://attester.example.com': jose.createRemoteJWKSet(new URL('https://attester.example.com/jwks')),
}));
function getAttestationSignaturePublicKey(ctx, iss, header, client) {
  if (attesters.has(iss)) return attesters.get(iss)(header);
  throw new Error('unsupported oauth-client-attestation issuer');
}
```
</details>

</details>

---

### features.backchannelLogout

[`OIDC Back-Channel Logout 1.0`](https://openid.net/specs/openid-connect-backchannel-1_0-final.html)  

Specifies whether Back-Channel Logout capabilities shall be enabled. When enabled, the authorization server shall support propagating end-user logouts initiated by relying parties to clients that were involved throughout the lifetime of the terminated session.  


_**default value**_:
```js
{
  enabled: false
}
```

---

### features.ciba

[OIDC Client Initiated Backchannel Authentication Flow (`CIBA`)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)  

Enables Core `CIBA` Flow, when combined with `features.fapi` and `features.requestObjects.enabled` enables [Financial-grade API: Client Initiated Backchannel Authentication Profile - Implementers Draft 01](https://openid.net/specs/openid-financial-api-ciba-ID1.html) as well.   
  


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

Specifies the token delivery modes supported by this authorization server. The following delivery modes are defined:
 - `poll` - Client polls the token endpoint for completion
 - `ping` - Authorization server notifies client of completion via HTTP callback   
  


_**default value**_:
```js
[
  'poll'
]
```

#### processLoginHint

Specifies a helper function that shall be invoked to process the `login_hint` parameter and extract the corresponding accountId value for request processing. This function MUST validate the hint format and content according to authorization server policy.   
  

_**recommendation**_: Use `throw new errors.InvalidRequest('validation error message')` when the login_hint format or content is invalid.  

_**recommendation**_: Use `return undefined` when the accountId cannot be determined from the provided login_hint.  


_**default value**_:
```js
async function processLoginHint(ctx, loginHint) {
  // @param ctx - koa request context
  // @param loginHint - string value of the login_hint parameter
  throw new Error('features.ciba.processLoginHint not implemented');
}
```

#### processLoginHintToken

Specifies a helper function that shall be invoked to process the `login_hint_token` parameter and extract the corresponding accountId value for request processing. This function MUST validate token expiration and format according to authorization server policy.   
  

_**recommendation**_: Use `throw new errors.ExpiredLoginHintToken('validation error message')` when the login_hint_token has expired.  

_**recommendation**_: Use `throw new errors.InvalidRequest('validation error message')` when the login_hint_token format or content is invalid.  

_**recommendation**_: Use `return undefined` when the accountId cannot be determined from the provided login_hint_token.  


_**default value**_:
```js
async function processLoginHintToken(ctx, loginHintToken) {
  // @param ctx - koa request context
  // @param loginHintToken - string value of the login_hint_token parameter
  throw new Error('features.ciba.processLoginHintToken not implemented');
}
```

#### triggerAuthenticationDevice

Specifies a helper function that shall be invoked to initiate authentication and authorization processes on the end-user's Authentication Device as defined in the CIBA specification. This function is executed after accepting the backchannel authentication request but before transmitting the response to the requesting client.   
 Upon successful end-user authentication, implementations shall use `provider.backchannelResult()` to complete the Consumption Device login process.   
  


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
<a id="trigger-authentication-device-provider-backchannel-result-method"></a><details><summary>Example: (Click to expand) `provider.backchannelResult()` method.</summary><br>


`backchannelResult` is a method on the Provider prototype, it returns a `Promise` with no fulfillment value.
  

```js
import * as oidc from 'oidc-provider';
const provider = new oidc.Provider(...);
await provider.backchannelResult(...);
```
`backchannelResult(request, result[, options]);`
 - `request` BackchannelAuthenticationRequest - BackchannelAuthenticationRequest instance.
 - `result` Grant | OIDCProviderError - instance of a persisted Grant model or an OIDCProviderError (all exported by errors).
 - `options.acr?`: string - Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied.
 - `options.amr?`: string[] - Identifiers for authentication methods used in the authentication.
 - `options.authTime?`: number - Time when the end-user authentication occurred.  


</details>

#### validateBindingMessage

Specifies a helper function that shall be invoked to validate the `binding_message` parameter according to authorization server policy. This function MUST reject invalid binding messages by throwing appropriate error instances.   
  

_**recommendation**_: Use `throw new errors.InvalidBindingMessage('validation error message')` when the binding_message violates authorization server policy.  

_**recommendation**_: Use `return undefined` when a binding_message is not required by policy and was not provided in the request.  


_**default value**_:
```js
async function validateBindingMessage(ctx, bindingMessage) {
  // @param ctx - koa request context
  // @param bindingMessage - string value of the binding_message parameter, when not provided it is undefined
  if (bindingMessage?.match(/^[a-zA-Z0-9-._+/!?#]{1,20}$/) === null) {
    throw new errors.InvalidBindingMessage(
      'the binding_message value, when provided, needs to be 1 - 20 characters in length and use only a basic set of characters (matching the regex: ^[a-zA-Z0-9-._+/!?#]{1,20}$ )',
    );
  }
}
```

#### validateRequestContext

Specifies a helper function that shall be invoked to validate the `request_context` parameter according to authorization server policy. This function MUST enforce policy requirements for request context validation and reject non-compliant requests.   
  

_**recommendation**_: Use `throw new errors.InvalidRequest('validation error message')` when the request_context is required by policy but missing or invalid.  

_**recommendation**_: Use `return undefined` when a request_context is not required by policy and was not provided in the request.  


_**default value**_:
```js
async function validateRequestContext(ctx, requestContext) {
  // @param ctx - koa request context
  // @param requestContext - string value of the request_context parameter, when not provided it is undefined
  throw new Error('features.ciba.validateRequestContext not implemented');
}
```

#### verifyUserCode

Specifies a helper function that shall be invoked to verify the presence and validity of the `user_code` parameter when required by authorization server policy.   
  

_**recommendation**_: Use `throw new errors.MissingUserCode('validation error message')` when user_code is required by policy but was not provided.  

_**recommendation**_: Use `throw new errors.InvalidUserCode('validation error message')` when the provided user_code value is invalid or does not meet policy requirements.  

_**recommendation**_: Use `return undefined` when no user_code was provided and it is not required by authorization server policy.  


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

---

### features.claimsParameter

[`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ClaimsParameter) - Requesting Claims using the "claims" Request Parameter  

Specifies whether the `claims` request parameter shall be enabled for authorization requests. When enabled, the authorization server shall accept and process the `claims` parameter to enable fine-grained control over which claims are returned in ID Tokens and from the UserInfo Endpoint.   
  


_**default value**_:
```js
{
  assertClaimsParameter: [AsyncFunction: assertClaimsParameter], // see expanded details below
  enabled: false
}
```

<details><summary>(Click to expand) features.claimsParameter options details</summary><br>


#### assertClaimsParameter

Specifies a helper function that shall be invoked to perform additional validation of the `claims` parameter. This function enables enforcement of deployment-specific policies, security constraints, or extended claim validation logic according to authorization server requirements.   
 The function may throw errors to reject non-compliant claims requests or return successfully to indicate acceptance of the claims parameter content.  


_**default value**_:
```js
async function assertClaimsParameter(ctx, claims, client) {
  // @param ctx - koa request context
  // @param claims - parsed claims parameter
  // @param client - the Client instance
}
```

</details>

---

### features.clientCredentials

[`RFC6749`](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3.4) - Client Credentials  

Specifies whether the Client Credentials grant type shall be enabled. When enabled, the authorization server shall accept `grant_type=client_credentials` requests at the token endpoint, allowing clients to obtain access tokens.  


_**default value**_:
```js
{
  enabled: false
}
```

---

### features.dPoP

[`RFC9449`](https://www.rfc-editor.org/rfc/rfc9449.html) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (`DPoP`)  

Enables sender-constraining of OAuth 2.0 tokens through application-level proof-of-possession mechanisms.  


_**default value**_:
```js
{
  allowReplay: false,
  enabled: true,
  nonceSecret: undefined,
  requireNonce: [Function: requireNonce] // see expanded details below
}
```

<details><summary>(Click to expand) features.dPoP options details</summary><br>


#### allowReplay

Specifies whether DPoP Proof replay shall be permitted by the authorization server. When set to false, the server enforces strict replay protection by rejecting previously used DPoP proofs, enhancing security against replay attacks.  


_**default value**_:
```js
false
```

#### nonceSecret

Specifies the cryptographic secret value used for generating server-provided DPoP nonces. When provided, this value MUST be a 32-byte length Buffer instance to ensure sufficient entropy for secure nonce generation.  


_**default value**_:
```js
undefined
```

#### requireNonce

Specifies a function that determines whether a DPoP nonce shall be required for proof-of-possession validation in the current request context. This function is invoked during DPoP proof validation to enforce nonce requirements based on authorization server policy.  


_**default value**_:
```js
function requireNonce(ctx) {
  return false;
}
```

</details>

---

### features.devInteractions

Enables development-only interaction views that provide pre-built user interface components for rapid prototyping and testing of authorization flows. These views accept any username (used as the subject claim value) and any password for authentication, bypassing production-grade security controls.   
 Production deployments MUST disable this feature and implement proper end-user authentication and authorization mechanisms. These development views MUST NOT be used in production environments as they provide no security guarantees and accept arbitrary credentials.  


_**default value**_:
```js
{
  enabled: true
}
```

---

### features.deviceFlow

[`RFC8628`](https://www.rfc-editor.org/rfc/rfc8628.html) - OAuth 2.0 Device Authorization Grant (`Device Flow`)  

Specifies whether the OAuth 2.0 Device Authorization Grant shall be enabled. When enabled, the authorization server shall support the device authorization flow, enabling OAuth clients on input-constrained devices to obtain user authorization by directing the user to perform the authorization flow on a secondary device with richer input and display capabilities.  


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

Specifies the character set used for generating user codes in the device authorization flow. This configuration determines the alphabet from which user codes are constructed. Supported values include:
 - `base-20` - Uses characters BCDFGHJKLMNPQRSTVWXZ (excludes easily confused characters)
 - `digits` - Uses characters 0123456789 (numeric only)  


_**default value**_:
```js
'base-20'
```

#### deviceInfo

Specifies a helper function that shall be invoked to extract device-specific information from device authorization endpoint requests. The extracted information becomes available during the end-user confirmation screen to assist users in verifying that the authorization request originated from a device in their possession. This enhances security by enabling users to confirm device identity before granting authorization.  


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

Specifies the template pattern used for generating user codes in the device authorization flow. The authorization server shall replace `*` characters with random characters from the configured charset, while `-` (dash) and ` ` (space) characters may be included for enhanced readability. Refer to RFC 8628 for guidance on minimal recommended entropy requirements for user code generation.  


_**default value**_:
```js
'****-****'
```

#### successSource

Specifies the HTML source that shall be rendered when the device flow feature displays a success page to the User-Agent. This template is presented upon successful completion of the device authorization flow to inform the end-user that authorization has been granted to the requesting device.  


_**default value**_:
```js
async function successSource(ctx) {
  // @param ctx - koa request context
  ctx.body = `<!DOCTYPE html>
    <html>
    <head>
      <title>Sign-in Success</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>Sign-in Success</h1>
        <p>Your sign-in ${ctx.oidc.client.clientName ? `with ${ctx.oidc.client.clientName}` : ''} was successful, you can now close this page.</p>
      </div>
    </body>
    </html>`;
}
```

#### userCodeConfirmSource

Specifies the HTML source that shall be rendered when the device flow feature displays a confirmation prompt to the User-Agent. This template is presented after successful user code validation to confirm the authorization request before proceeding with the device authorization flow.  


_**default value**_:
```js
async function userCodeConfirmSource(ctx, form, client, deviceInfo, userCode) {
  // @param ctx - koa request context
  // @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
  //   submitted by the End-User.
  // @param deviceInfo - device information from the device_authorization_endpoint call
  // @param userCode - formatted user code by the configured mask
  ctx.body = `<!DOCTYPE html>
    <html>
    <head>
      <title>Device Login Confirmation</title>
      <style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>
    </head>
    <body>
      <div>
        <h1>Confirm Device</h1>
        <p>
          <strong>${ctx.oidc.client.clientName || ctx.oidc.client.clientId}</strong>
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

Specifies the HTML source that shall be rendered when the device flow feature displays a user code input prompt to the User-Agent. This template is presented during the device authorization flow when the authorization server requires the end-user to enter a device-generated user code for verification.  


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
    <html>
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

---

### features.encryption

Specifies whether encryption capabilities shall be enabled. When enabled, the authorization server shall support accepting and issuing encrypted tokens involved in its other enabled capabilities.  


_**default value**_:
```js
{
  enabled: false
}
```

---

### features.externalSigningSupport

External Signing Support  

> [!NOTE]
> This is an experimental feature.

Specifies whether external signing capabilities shall be enabled. When enabled, the authorization server shall support the use of `ExternalSigningKey` class instances in place of private JWK entries within the `jwks.keys` configuration array. This feature enables Digital Signature Algorithm operations (such as PS256, ES256, or other supported algorithms) to be performed by external cryptographic services, including Key Management Services (KMS) and Hardware Security Modules (HSM), providing enhanced security for private key material through externalized signing operations.   
  

See [KMS integration with AWS Key Management Service](https://github.com/panva/node-oidc-provider/discussions/1316)

_**default value**_:
```js
{
  ack: undefined,
  enabled: false
}
```

---

### features.fapi

FAPI Security Profiles (`FAPI`)  

Specifies whether FAPI Security Profile capabilities shall be enabled. When enabled, the authorization server shall implement additional security behaviors defined in FAPI specifications that cannot be achieved through other configuration options.  


_**default value**_:
```js
{
  enabled: false,
  profile: undefined
}
```

<details><summary>(Click to expand) features.fapi options details</summary><br>


#### profile

Specifies the FAPI profile version that shall be applied for security policy enforcement. The authorization server shall implement the behaviors defined in the selected profile specification. Supported values include:   
 - '2.0' - The authorization server shall implement behaviors from [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
 - '1.0 Final' - The authorization server shall implement behaviors from [FAPI 1.0 Security Profile - Part 2: Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0-final.html)
 - Function - A function that shall be invoked with arguments `(ctx, client)` to determine the profile contextually. The function shall return one of the supported profile values or undefined when FAPI behaviors should be ignored for the current request context.  


_**default value**_:
```js
undefined
```

</details>

---

### features.introspection

[`RFC7662`](https://www.rfc-editor.org/rfc/rfc7662.html) - OAuth 2.0 Token Introspection  

Specifies whether OAuth 2.0 Token Introspection capabilities shall be enabled. When enabled, the authorization server shall expose a token introspection endpoint that allows authorized clients and resource servers to query the metadata and status of the following token types:
 - Opaque access tokens
 - Refresh tokens   
  


_**default value**_:
```js
{
  allowedPolicy: [AsyncFunction: introspectionAllowedPolicy], // see expanded details below
  enabled: false
}
```

<details><summary>(Click to expand) features.introspection options details</summary><br>


#### allowedPolicy

Specifies a helper function that shall be invoked to determine whether the requesting client or resource server is authorized to introspect the specified token. This function enables enforcement of fine-grained access control policies for token introspection operations according to authorization server security requirements.  


_**default value**_:
```js
async function introspectionAllowedPolicy(ctx, client, token) {
  // @param ctx - koa request context
  // @param client - authenticated client making the request
  // @param token - token being introspected
  if (
    client.clientAuthMethod === 'none'
    && token.clientId !== ctx.oidc.client.clientId
  ) {
    return false;
  }
  return true;
}
```

</details>

---

### features.jwtIntrospection

[`RFC9701`](https://www.rfc-editor.org/rfc/rfc9701.html) - JWT Response for OAuth Token Introspection  

Specifies whether JWT-formatted token introspection responses shall be enabled. When enabled, the authorization server shall support issuing introspection responses as JSON Web Tokens, providing enhanced security and integrity protection for token metadata transmission between authorized parties.  


_**default value**_:
```js
{
  enabled: false
}
```

---

### features.jwtResponseModes

[JWT Secured Authorization Response Mode (`JARM`)](https://openid.net/specs/oauth-v2-jarm-final.html)  

Specifies whether JWT Secured Authorization Response Mode capabilities shall be enabled. When enabled, the authorization server shall support encoding authorization responses as JSON Web Tokens, providing cryptographic protection and integrity assurance for authorization response parameters.  


_**default value**_:
```js
{
  enabled: false
}
```

---

### features.jwtUserinfo

[`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfo) - JWT UserInfo Endpoint Responses  

Specifies whether JWT-formatted UserInfo endpoint responses shall be enabled. When enabled, the authorization server shall support returning UserInfo responses as signed and/or encrypted JSON Web Tokens, providing enhanced security and integrity protection for end-user claims transmission. This feature shall also enable the relevant client metadata parameters for configuring JWT signing and/or encryption algorithms according to client requirements.  


_**default value**_:
```js
{
  enabled: false
}
```

---

### features.mTLS

[`RFC8705`](https://www.rfc-editor.org/rfc/rfc8705.html) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens (`MTLS`)  

Specifies whether Mutual TLS capabilities shall be enabled. The authorization server supports three distinct features that require separate configuration settings within this feature's configuration object. Implementations MUST provide deployment-specific helper functions for certificate validation and processing operations.   
  


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

Specifies a helper function that shall be invoked to determine whether the client certificate used in the request is verified and originates from a trusted Certificate Authority for the requesting client. This function MUST return a boolean value indicating certificate authorization status. This validation is exclusively used for the `tls_client_auth` client authentication method.  


_**default value**_:
```js
function certificateAuthorized(ctx) {
  throw new Error('features.mTLS.certificateAuthorized function not configured');
}
```

#### certificateBoundAccessTokens

Specifies whether Certificate-Bound Access Tokens shall be enabled as defined in RFC 8705 sections 3 and 4. When enabled, the authorization server shall expose the client's `tls_client_certificate_bound_access_tokens` metadata property for mutual TLS certificate binding functionality.  


_**default value**_:
```js
false
```

#### certificateSubjectMatches

Specifies a helper function that shall be invoked to determine whether the client certificate subject used in the request matches the registered client property according to authorization server policy. This function MUST return a boolean value indicating subject matching status. This validation is exclusively used for the `tls_client_auth` client authentication method.  


_**default value**_:
```js
function certificateSubjectMatches(ctx, property, expected) {
  throw new Error('features.mTLS.certificateSubjectMatches function not configured');
}
```

#### getCertificate

Specifies a helper function that shall be invoked to retrieve the client certificate used in the current request. This function MUST return either a `crypto.X509Certificate` instance or a PEM-formatted string representation of the client certificate for mutual TLS processing.  


_**default value**_:
```js
function getCertificate(ctx) {
  throw new Error('features.mTLS.getCertificate function not configured');
}
```

#### selfSignedTlsClientAuth

Specifies whether Self-Signed Certificate Mutual TLS client authentication shall be enabled as defined in RFC 8705 section 2.2. When enabled, the authorization server shall support the `self_signed_tls_client_auth` authentication method within the server's `clientAuthMethods` configuration.  


_**default value**_:
```js
false
```

#### tlsClientAuth

Specifies whether PKI Mutual TLS client authentication shall be enabled as defined in RFC 8705 section 2.1. When enabled, the authorization server shall support the `tls_client_auth` authentication method within the server's `clientAuthMethods` configuration.  


_**default value**_:
```js
false
```

</details>

---

### features.pushedAuthorizationRequests

[`RFC9126`](https://www.rfc-editor.org/rfc/rfc9126.html) - OAuth 2.0 Pushed Authorization Requests (`PAR`)  

Specifies whether Pushed Authorization Request capabilities shall be enabled. When enabled, the authorization server shall expose a pushed authorization request endpoint that allows clients to lodge authorization request parameters at the authorization server prior to redirecting end-users to the authorization endpoint, enhancing security by removing the need to transmit parameters via query string parameters.  


_**default value**_:
```js
{
  allowUnregisteredRedirectUris: false,
  enabled: true,
  requirePushedAuthorizationRequests: false
}
```

<details><summary>(Click to expand) features.pushedAuthorizationRequests options details</summary><br>


#### allowUnregisteredRedirectUris

Specifies whether unregistered redirect_uri values shall be permitted for authenticated clients using PAR that do not utilize a sector_identifier_uri. This configuration enables dynamic redirect URI specification within the security constraints of the pushed authorization request mechanism.  


_**default value**_:
```js
false
```

#### requirePushedAuthorizationRequests

Specifies whether PAR usage shall be mandatory for all authorization requests as an authorization server security policy. When enabled, the authorization server shall reject authorization endpoint requests that do not utilize the pushed authorization request mechanism.  


_**default value**_:
```js
false
```

</details>

---

### features.registration

[`OIDC Dynamic Client Registration 1.0`](https://openid.net/specs/openid-connect-registration-1_0-errata2.html) and [`RFC7591`](https://www.rfc-editor.org/rfc/rfc7591.html) - OAuth 2.0 Dynamic Client Registration Protocol  

Specifies whether Dynamic Client Registration capabilities shall be enabled. When enabled, the authorization server shall expose a client registration endpoint that allows clients to dynamically register themselves with the authorization server at runtime, enabling automated client onboarding and configuration management.  


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

Specifies a helper function that shall be invoked to generate random client identifiers during dynamic client registration operations. This function enables customization of client identifier generation according to authorization server requirements and conventions.  


_**default value**_:
```js
function idFactory(ctx) {
  return nanoid();
}
```

#### initialAccessToken

Specifies whether the registration endpoint shall require an initial access token as authorization for client registration requests. This configuration controls access to the dynamic registration functionality. Supported values include:
 - `string` - The authorization server shall validate the provided bearer token against this static initial access token value
 - `boolean` - When true, the authorization server shall require adapter-backed initial access tokens; when false, registration requests are processed without initial access tokens.   
  


_**default value**_:
```js
false
```
<a id="initial-access-token-to-add-an-adapter-backed-initial-access-token-and-retrive-its-value"></a><details><summary>Example: (Click to expand) To add an adapter backed initial access token and retrive its value.</summary><br>

```js
new (provider.InitialAccessToken)({}).save().then(console.log);
```
</details>

#### issueRegistrationAccessToken

Specifies whether a registration access token shall be issued upon successful client registration. This configuration determines if clients receive tokens for subsequent registration management operations. Supported values include:
 - `true` - Registration access tokens shall be issued for all successful registrations
 - `false` - Registration access tokens shall not be issued
 - Function - A function that shall be invoked to dynamically determine token issuance based on request context and authorization server policy   
  


_**default value**_:
```js
true
```
<a id="issue-registration-access-token-to-determine-if-a-registration-access-token-should-be-issued-dynamically"></a><details><summary>Example: (Click to expand) To determine if a registration access token should be issued dynamically.</summary><br>

```js
// @param ctx - koa request context
async issueRegistrationAccessToken(ctx) {
  return policyImplementation(ctx)
}
```
</details>

#### policies

Specifies registration and registration management policies that shall be applied to client metadata properties during dynamic registration operations. Policies are synchronous or asynchronous functions assigned to Initial Access Tokens that execute before standard client property validations. Multiple policies may be assigned to an Initial Access Token, and by default, the same policies shall transfer to the Registration Access Token. Policy functions may throw errors to reject registration requests or modify the client properties object before validation.   
  

_**recommendation**_: Referenced policies MUST always be present when encountered on a token; an AssertionError will be thrown inside the request context if a policy is not found, resulting in a 500 Server Error.  

_**recommendation**_: The same policies will be assigned to the Registration Access Token after a successful validation. If you wish to assign different policies to the Registration Access Token:
 ```js
 // inside your final ran policy
 ctx.oidc.entities.RegistrationAccessToken.policies = ['update-policy'];
 ```  


_**default value**_:
```js
undefined
```
<a id="policies-to-define-registration-and-registration-management-policies"></a><details><summary>Example: (Click to expand) To define registration and registration management policies.</summary><br>


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
        throw new errors.InvalidClientMetadata('validation error message');
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

Specifies a helper function that shall be invoked to generate random client secrets during dynamic client registration operations. This function enables customization of client secret generation according to authorization server security requirements and entropy specifications.  


_**default value**_:
```js
async function secretFactory(ctx) {
  return crypto.randomBytes(64).toString('base64url');
}
```

</details>

---

### features.registrationManagement

[`RFC7592`](https://www.rfc-editor.org/rfc/rfc7592.html) - OAuth 2.0 Dynamic Client Registration Management Protocol  

Specifies whether Dynamic Client Registration Management capabilities shall be enabled. When enabled, the authorization server shall expose Update and Delete operations as defined in RFC 7592, allowing clients to modify or remove their registration entries using Registration Access Tokens for client lifecycle management operations.  


_**default value**_:
```js
{
  enabled: false,
  rotateRegistrationAccessToken: true
}
```

<details><summary>(Click to expand) features.registrationManagement options details</summary><br>


#### rotateRegistrationAccessToken

Specifies whether registration access token rotation shall be enabled as a security policy for client registration management operations. When token rotation is active, the authorization server shall discard the current Registration Access Token upon successful update operations and issue a new token, returning it to the client with the Registration Update Response.   
 Supported values include:
 - `false` - Registration access tokens shall not be rotated and remain valid after use
 - `true` - Registration access tokens shall be rotated when used for management operations
 - Function - A function that shall be invoked to dynamically determine whether rotation should occur based on request context and authorization server policy   
  


_**default value**_:
```js
true
```
<a id="rotate-registration-access-token-dynamic-token-rotation-policy-implementation"></a><details><summary>Example: (Click to expand) Dynamic token rotation policy implementation.</summary><br>

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

---

### features.requestObjects

[`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#RequestObject) and [`RFC9101`](https://www.rfc-editor.org/rfc/rfc9101.html#name-passing-a-request-object-by) - Passing a Request Object by Value (`JAR`)  

Specifies whether Request Object capabilities shall be enabled. When enabled, the authorization server shall support the use and validation of the `request` parameter for conveying authorization request parameters as JSON Web Tokens, providing enhanced security and integrity protection for authorization requests.  


_**default value**_:
```js
{
  assertJwtClaimsAndHeader: [AsyncFunction: assertJwtClaimsAndHeader], // see expanded details below
  enabled: false,
  requireSignedRequestObject: false
}
```

<details><summary>(Click to expand) features.requestObjects options details</summary><br>


#### assertJwtClaimsAndHeader

Specifies a helper function that shall be invoked to perform additional validation of the Request Object JWT Claims Set and Header beyond the standard JAR specification requirements. This function enables enforcement of deployment-specific policies, security constraints, or extended validation logic according to authorization server requirements.  


_**default value**_:
```js
async function assertJwtClaimsAndHeader(ctx, claims, header, client) {
  // @param ctx - koa request context
  // @param claims - parsed Request Object JWT Claims Set as object
  // @param header - parsed Request Object JWT Headers as object
  // @param client - the Client instance
  const requiredClaims = [];
  const fapiProfile = ctx.oidc.isFapi('1.0 Final', '2.0');
  if (fapiProfile) {
    requiredClaims.push('exp', 'aud', 'nbf');
  }
  if (ctx.oidc.route === 'backchannel_authentication') {
    requiredClaims.push('exp', 'iat', 'nbf', 'jti');
  }
  for (const claim of new Set(requiredClaims)) {
    if (claims[claim] === undefined) {
      throw new errors.InvalidRequestObject(
        `Request Object is missing the '${claim}' claim`,
      );
    }
  }
  if (fapiProfile) {
    const diff = claims.exp - claims.nbf;
    if (Math.sign(diff) !== 1 || diff > 3600) {
      throw new errors.InvalidRequestObject(
        "Request Object 'exp' claim too far from 'nbf' claim",
      );
    }
  }
}
```

#### requireSignedRequestObject

Specifies whether the use of signed request objects shall be mandatory for all authorization requests as an authorization server security policy. When enabled, the authorization server shall reject authorization requests that do not include a signed Request Object JWT.  


_**default value**_:
```js
false
```

</details>

---

### features.resourceIndicators

[`RFC8707`](https://www.rfc-editor.org/rfc/rfc8707.html) - Resource Indicators for OAuth 2.0  

Specifies whether Resource Indicator capabilities shall be enabled. When enabled, the authorization server shall support the `resource` parameter at the authorization and token endpoints to enable issuing Access Tokens for specific Resource Servers (APIs) with enhanced audience control and scope management.   
 The authorization server implements the following resource indicator processing rules:
 - Multiple resource parameters may be present during Authorization Code Flow, Device Authorization Grant, and Backchannel Authentication Requests, but only a single audience for an Access Token is permitted.
 - Authorization and Authentication Requests that result in an Access Token being issued by the Authorization Endpoint MUST only contain a single resource (or one MUST be resolved using the `defaultResource` helper).
 - Client Credentials grant MUST only contain a single resource parameter.
 - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request exchanges, if the exchanged code/token does not include the `'openid'` scope and only has a single resource then the resource parameter may be omitted - an Access Token for the single resource is returned.
 - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request exchanges, if the exchanged code/token does not include the `'openid'` scope and has multiple resources then the resource parameter MUST be provided (or one MUST be resolved using the `defaultResource` helper). An Access Token for the provided/resolved resource is returned.
 - (with userinfo endpoint enabled and useGrantedResource helper returning falsy) During Authorization Code / Refresh Token / Device Code exchanges, if the exchanged code/token includes the `'openid'` scope and no resource parameter is present - an Access Token for the UserInfo Endpoint is returned.
 - (with userinfo endpoint enabled and useGrantedResource helper returning truthy) During Authorization Code / Refresh Token / Device Code exchanges, even if the exchanged code/token includes the `'openid'` scope and only has a single resource then the resource parameter may be omitted - an Access Token for the single resource is returned.
 - (with userinfo endpoint disabled) During Authorization Code / Refresh Token / Device Code exchanges, if the exchanged code/token includes the `'openid'` scope and only has a single resource then the resource parameter may be omitted - an Access Token for the single resource is returned.
 - Issued Access Tokens shall always only contain scopes that are defined on the respective Resource Server (returned from `features.resourceIndicators.getResourceServerInfo`).  


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

Specifies a helper function that shall be invoked to determine the default resource indicator for a request when none is provided by the client during the authorization request or when multiple resources are provided/resolved and only a single one is required during an Access Token Request. This function enables authorization server policy-based resource selection according to deployment requirements.  


_**default value**_:
```js
async function defaultResource(ctx, client, oneOf) {
  // @param ctx - koa request context
  // @param client - client making the request
  // @param oneOf {string[]} - The authorization server needs to select **one** of the values provided.
  //                           Default is that the array is provided so that the request will fail.
  //                           This argument is only provided when called during
  //                           Authorization Code / Refresh Token / Device Code exchanges.
  if (oneOf) return oneOf;
  return undefined;
}
```

#### getResourceServerInfo

Specifies a helper function that shall be invoked to load information about a Resource Server (API) and determine whether the client is authorized to request scopes for that particular resource. This function enables resource-specific scope validation and Access Token configuration according to authorization server policy.   
  

_**recommendation**_: Only allow client's pre-registered resource values. To pre-register these you shall use the `extraClientMetadata` configuration option to define a custom metadata and use that to implement your policy using this function.  


_**default value**_:
```js
async function getResourceServerInfo(ctx, resourceIndicator, client) {
  // @param ctx - koa request context
  // @param resourceIndicator - resource indicator value either requested or resolved by the defaultResource helper.
  // @param client - client making the request
  throw new errors.InvalidTarget();
}
```
<a id="get-resource-server-info-resource-server-definition"></a><details><summary>Example: (Click to expand) Resource Server Definition.</summary><br>

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
  accessTokenFormat?: 'opaque' | 'jwt',
  // JWT Access Token Format (when accessTokenFormat is 'jwt')
  // Default is `{ sign: { alg: 'RS256' }, encrypt: false }`
  // Tokens may be signed, signed and then encrypted, or just encrypted JWTs.
  jwt?: {
    // Tokens will be signed
    sign?:
     | {
         alg?: string, // 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES384' | 'ES512' | 'Ed25519' | 'RS256' | 'RS384' | 'RS512' | 'EdDSA'
         kid?: string, // OPTIONAL `kid` to aid in signing key selection
       }
     | {
         alg: string, // 'HS256' | 'HS384' | 'HS512'
         key: CryptoKey | KeyObject | Buffer, // shared symmetric secret to sign the JWT token with
         kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWS Header
       },
    // Tokens will be encrypted
    encrypt?: {
      alg: string, // 'dir' | 'RSA-OAEP' | 'RSA-OAEP-256' | 'RSA-OAEP-384' | 'RSA-OAEP-512' | 'ECDH-ES' | 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW' | 'A128KW' | 'A192KW' | 'A256KW' | 'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW'
      enc: string, // 'A128CBC-HS256' | 'A128GCM' | 'A192CBC-HS384' | 'A192GCM' | 'A256CBC-HS512' | 'A256GCM'
      key: CryptoKey | KeyObject | Buffer, // public key or shared symmetric secret to encrypt the JWT token with
      kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWE Header
    }
  }
}
```
</details>
<a id="get-resource-server-info-resource-server-api-with-two-scopes-an-expected-audience-value-an-access-token-ttl-and-a-jwt-access-token-format"></a><details><summary>Example: (Click to expand) Resource Server (API) with two scopes, an expected audience value, an Access Token TTL and a JWT Access Token Format.</summary><br>

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
<a id="get-resource-server-info-resource-server-api-with-two-scopes-and-a-symmetrically-encrypted-jwt-access-token-format"></a><details><summary>Example: (Click to expand) Resource Server (API) with two scopes and a symmetrically encrypted JWT Access Token Format.</summary><br>

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

#### useGrantedResource

Specifies a helper function that shall be invoked to determine whether an already granted resource indicator should be used without being explicitly requested by the client during the Token Endpoint request. This function enables flexible resource selection policies for token issuance operations.   
  

_**recommendation**_: Use `return true` when it's allowed for a client to skip providing the "resource" parameter at the Token Endpoint.  

_**recommendation**_: Use `return false` (default) when it's required for a client to explicitly provide a "resource" parameter at the Token Endpoint or when other indication dictates an Access Token for the UserInfo Endpoint should be returned.  


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

---

### features.revocation

[`RFC7009`](https://www.rfc-editor.org/rfc/rfc7009.html) - OAuth 2.0 Token Revocation  

Specifies whether Token Revocation capabilities shall be enabled. When enabled, the authorization server shall expose a token revocation endpoint that allows authorized clients and resource servers to notify the authorization server that a particular token is no longer needed. This feature supports revocation of the following token types:
 - Opaque access tokens
 - Refresh tokens   
  


_**default value**_:
```js
{
  allowedPolicy: [AsyncFunction: revocationAllowedPolicy], // see expanded details below
  enabled: false
}
```

<details><summary>(Click to expand) features.revocation options details</summary><br>


#### allowedPolicy

Specifies a helper function that shall be invoked to determine whether the requesting client or resource server is authorized to revoke the specified token. This function enables enforcement of fine-grained access control policies for token revocation operations according to authorization server security requirements.  


_**default value**_:
```js
async function revocationAllowedPolicy(ctx, client, token) {
  // @param ctx - koa request context
  // @param client - authenticated client making the request
  // @param token - token being revoked
  if (token.clientId !== client.clientId) {
    if (client.clientAuthMethod === 'none') {
      // do not revoke but respond as success to disallow guessing valid tokens
      return false;
    }
    throw new errors.InvalidRequest('client is not authorized to revoke the presented token');
  }
  return true;
}
```

</details>

---

### features.richAuthorizationRequests

[`RFC9396`](https://www.rfc-editor.org/rfc/rfc9396.html) - OAuth 2.0 Rich Authorization Requests  

> [!NOTE]
> This is an experimental feature.

Specifies whether Rich Authorization Request capabilities shall be enabled. When enabled, the authorization server shall support the `authorization_details` parameter at the authorization and token endpoints to enable issuing Access Tokens with fine-grained authorization data and enhanced authorization scope control.  


_**default value**_:
```js
{
  ack: undefined,
  enabled: false,
  rarForAuthorizationCode: [Function: rarForAuthorizationCode], // see expanded details below
  rarForCodeResponse: [Function: rarForCodeResponse], // see expanded details below
  rarForIntrospectionResponse: [Function: rarForIntrospectionResponse], // see expanded details below
  rarForRefreshTokenResponse: [Function: rarForRefreshTokenResponse], // see expanded details below
  types: {}
}
```

<details><summary>(Click to expand) features.richAuthorizationRequests options details</summary><br>


#### rarForAuthorizationCode

Specifies a helper function that shall be invoked to transform the requested and granted Rich Authorization Request details for storage in the authorization code. This function enables filtering and processing of authorization details according to authorization server policy before code persistence. The function shall return an array of authorization details or undefined.  


_**default value**_:
```js
rarForAuthorizationCode(ctx) {
  // decision points:
  // - ctx.oidc.client
  // - ctx.oidc.resourceServers
  // - ctx.oidc.params.authorization_details (unparsed authorization_details from the authorization request)
  // - ctx.oidc.grant.rar (authorization_details granted)
  throw new Error(
    'features.richAuthorizationRequests.rarForAuthorizationCode not implemented',
  );
}
```

#### rarForCodeResponse

Specifies a helper function that shall be invoked to transform the requested and granted Rich Authorization Request details for inclusion in the Access Token Response as authorization_details and assignment to the issued Access Token. This function enables resource-specific filtering and transformation of authorization details according to token endpoint policy. The function shall return an array of authorization details or undefined.  


_**default value**_:
```js
rarForCodeResponse(ctx, resourceServer) {
  // decision points:
  // - ctx.oidc.client
  // - resourceServer
  // - ctx.oidc.authorizationCode.rar (previously returned from rarForAuthorizationCode)
  // - ctx.oidc.params.authorization_details (unparsed authorization_details from the body params in the Access Token Request)
  // - ctx.oidc.grant.rar (authorization_details granted)
  throw new Error(
    'features.richAuthorizationRequests.rarForCodeResponse not implemented',
  );
}
```

#### rarForIntrospectionResponse

Specifies a helper function that shall be invoked to transform the token's stored Rich Authorization Request details for inclusion in the Token Introspection Response. This function enables filtering and processing of authorization details according to introspection endpoint policy and requesting party authorization. The function shall return an array of authorization details or undefined.  


_**default value**_:
```js
rarForIntrospectionResponse(ctx, token) {
  // decision points:
  // - ctx.oidc.client
  // - token.kind
  // - token.rar
  // - ctx.oidc.grant.rar
  throw new Error(
    'features.richAuthorizationRequests.rarForIntrospectionResponse not implemented',
  );
}
```

#### rarForRefreshTokenResponse

Specifies a helper function that shall be invoked to transform the requested and granted Rich Authorization Request details for inclusion in the Access Token Response during refresh token exchanges as authorization_details and assignment to the newly issued Access Token. This function enables resource-specific processing of previously granted authorization details according to refresh token policy. The function shall return an array of authorization details or undefined.  


_**default value**_:
```js
rarForRefreshTokenResponse(ctx, resourceServer) {
  // decision points:
  // - ctx.oidc.client
  // - resourceServer
  // - ctx.oidc.refreshToken.rar (previously returned from rarForAuthorizationCode and later assigned to the refresh token)
  // - ctx.oidc.params.authorization_details (unparsed authorization_details from the body params in the Access Token Request)
  // - ctx.oidc.grant.rar
  throw new Error(
    'features.richAuthorizationRequests.rarForRefreshTokenResponse not implemented',
  );
}
```

#### types

Specifies the authorization details type identifiers that shall be supported by the authorization server. Each type identifier MUST have an associated validation function that defines the required structure and constraints for authorization details of that specific type according to authorization server policy.   
  


_**default value**_:
```js
{}
```
<a id="types-authorization-details-type-validation-for-tax-data-access"></a><details><summary>Example: (Click to expand) Authorization details type validation for tax data access.</summary><br>

```js
import { z } from 'zod'
const TaxData = z
  .object({
    duration_of_access: z.number().int().positive(),
    locations: z
      .array(
        z.literal('https://taxservice.govehub.no.example.com'),
      )
      .length(1),
    actions: z
      .array(z.literal('read_tax_declaration'))
      .length(1),
    periods: z
      .array(
        z.coerce
          .number()
          .max(new Date().getFullYear() - 1)
          .min(1997),
      )
      .min(1),
    tax_payer_id: z.string().min(1),
  })
  .strict()
const configuration = {
  features: {
    richAuthorizationRequests: {
      enabled: true,
      // ...
      types: {
        tax_data: {
          validate(ctx, detail, client) {
            const { success: valid, error } =
              TaxData.parse(detail)
            if (!valid) {
              throw new InvalidAuthorizationDetails()
            }
          },
        },
      },
    },
  },
}
```
</details>

</details>

---

### features.rpInitiatedLogout

[`OIDC RP-Initiated Logout 1.0`](https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html)  

Specifies whether RP-Initiated Logout capabilities shall be enabled. When enabled, the authorization server shall support logout requests initiated by relying parties, allowing clients to request termination of end-user sessions.  


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

Specifies the HTML source that shall be rendered when RP-Initiated Logout displays a confirmation prompt to the User-Agent. This template shall be presented to request explicit end-user confirmation before proceeding with the logout operation, ensuring user awareness and consent for session termination.  


_**default value**_:
```js
async function logoutSource(ctx, form) {
  // @param ctx - koa request context
  // @param form - form source (id="op.logoutForm") to be embedded in the page and submitted by
  //   the End-User
  ctx.body = `<!DOCTYPE html>
    <html>
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

Specifies the HTML source that shall be rendered when an RP-Initiated Logout request concludes successfully but no `post_logout_redirect_uri` was provided by the requesting client. This template shall be presented to inform the end-user that the logout operation has completed successfully and provide appropriate post-logout guidance.  


_**default value**_:
```js
async function postLogoutSuccessSource(ctx) {
  // @param ctx - koa request context
  const display = ctx.oidc.client?.clientName || ctx.oidc.client?.clientId;
  ctx.body = `<!DOCTYPE html>
    <html>
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

---

### features.rpMetadataChoices

[`OIDC Relying Party Metadata Choices 1.0 - Implementers Draft 01`](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-ID1.html)  

> [!NOTE]
> This is an experimental feature.

Specifies whether Relying Party Metadata Choices capabilities shall be enabled. When enabled, the authorization server shall support the following multi-valued input parameters metadata from the Relying Party Metadata Choices draft, provided that their underlying feature is also enabled:   
 - subject_types_supported
 - id_token_signing_alg_values_supported
 - id_token_encryption_alg_values_supported
 - id_token_encryption_enc_values_supported
 - userinfo_signing_alg_values_supported
 - userinfo_encryption_alg_values_supported
 - userinfo_encryption_enc_values_supported
 - request_object_signing_alg_values_supported
 - request_object_encryption_alg_values_supported
 - request_object_encryption_enc_values_supported
 - token_endpoint_auth_methods_supported
 - token_endpoint_auth_signing_alg_values_supported
 - introspection_signing_alg_values_supported
 - introspection_encryption_alg_values_supported
 - introspection_encryption_enc_values_supported
 - authorization_signing_alg_values_supported
 - authorization_encryption_alg_values_supported
 - authorization_encryption_enc_values_supported
 - backchannel_authentication_request_signing_alg_values_supported  


_**default value**_:
```js
{
  ack: undefined,
  enabled: false
}
```

---

### features.userinfo

[`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfo) - UserInfo Endpoint  

Specifies whether the UserInfo Endpoint shall be enabled. When enabled, the authorization server shall expose a UserInfo endpoint that returns claims about the authenticated end-user. Access to this endpoint requires an opaque Access Token with at least `openid` scope that does not have a Resource Server audience.  


_**default value**_:
```js
{
  enabled: true
}
```

---

### features.webMessageResponseMode

[draft-sakimura-oauth-wmrm-01](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-01) - OAuth 2.0 Web Message Response Mode  

> [!NOTE]
> This is an experimental feature.

Specifies whether Web Message Response Mode capabilities shall be enabled. When enabled, the authorization server shall support the `web_message` response mode for returning authorization responses via HTML5 Web Messaging. The implementation shall support only Simple Mode operation; authorization requests containing Relay Mode parameters will be rejected.   
  

_**recommendation**_: Although a general advise to use a `helmet` (e.g. for [express](https://www.npmjs.com/package/helmet), [koa](https://www.npmjs.com/package/koa-helmet)) it is especially advised for your interaction views routes if Web Message Response Mode is enabled in your deployment. You will have to experiment with removal of the Cross-Origin-Embedder-Policy and Cross-Origin-Opener-Policy headers at various endpoints throughout the authorization request end-user journey to finalize this feature.  


_**default value**_:
```js
{
  ack: undefined,
  enabled: false
}
```

---

### acceptQueryParamAccessTokens

Controls whether access tokens may be transmitted via URI query parameters. Several OAuth 2.0 and OpenID Connect profiles require that access tokens be transmitted exclusively via the Authorization header. When set to false, the authorization server shall reject requests attempting to transmit access tokens via query parameters.   
  


_**default value**_:
```js
false
```

---

### acrValues

An array of strings representing the Authentication Context Class References that this authorization server supports.  


_**default value**_:
```js
[]
```

---

### allowOmittingSingleRegisteredRedirectUri

Redirect URI Parameter Omission for Single Registered URI  

Specifies whether clients may omit the `redirect_uri` parameter in authorization requests when only a single redirect URI is registered in their client metadata. When enabled, the authorization server shall automatically use the sole registered redirect URI for clients that have exactly one URI configured.   
 When disabled, all authorization requests MUST explicitly include the `redirect_uri` parameter regardless of the number of registered redirect URIs.  


_**default value**_:
```js
true
```

---

### assertJwtClientAuthClaimsAndHeader

Specifies a helper function that shall be invoked to perform additional validation of JWT Client Authentication assertion Claims Set and Header beyond the requirements mandated by the specification. This function enables enforcement of deployment-specific security policies and extended validation logic for `private_key_jwt` and `client_secret_jwt` client authentication methods according to authorization server requirements.  


_**default value**_:
```js
async function assertJwtClientAuthClaimsAndHeader(ctx, claims, header, client) {
  // @param ctx - koa request context
  // @param claims - parsed JWT Client Authentication Assertion Claims Set as object
  // @param header - parsed JWT Client Authentication Assertion Headers as object
  // @param client - the Client instance
  if (ctx.oidc.isFapi('2.0') && claims.aud !== ctx.oidc.issuer) {
    throw new errors.InvalidClientAuth(
      'audience (aud) must equal the issuer identifier url',
    );
  }
}
```

---

### claims

Describes the claims that this authorization server may be able to supply values for.   
 It is used to achieve two different things related to claims:
 - which additional claims are available to RPs (configure as `{ claimName: null }`)
 - which claims fall under what scope (configure `{ scopeName: ['claim', 'another-claim'] }`)   
  

See [Configuring OpenID Connect 1.0 Standard Claims](https://github.com/panva/node-oidc-provider/discussions/1299)

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

---

### clientAuthMethods

Specifies the client authentication methods that this authorization server shall support for authenticating clients at the token endpoint and other authenticated endpoints.   
  


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
<a id="client-auth-methods-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'none',
  'client_secret_basic', 'client_secret_post',
  'client_secret_jwt', 'private_key_jwt',
  'tls_client_auth', 'self_signed_tls_client_auth', // these methods are only available when features.mTLS is configured
]
```
</details>

---

### clientBasedCORS

Specifies a function that determines whether Cross-Origin Resource Sharing (CORS) requests shall be permitted based on the requesting client. This function is invoked for each CORS preflight and actual request to evaluate the client's authorization to access the authorization server from the specified origin.   
  

See [Configuring Client Metadata-based CORS Origin allow list](https://github.com/panva/node-oidc-provider/discussions/1298)

_**default value**_:
```js
function clientBasedCORS(ctx, origin, client) {
  if (ctx.oidc.route === 'userinfo' || client.clientAuthMethod === 'none') {
    return client.redirectUris.some((uri) => URL.parse(uri)?.origin === origin);
  }
  return false;
}
```

---

### clientDefaults

Specifies default client metadata values that shall be applied when properties are not explicitly provided during Dynamic Client Registration or for statically configured clients. This configuration allows override of the authorization server's built-in default values for any supported client metadata property.   
  


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
<a id="client-defaults-changing-the-default-client-token-endpoint-auth-method"></a><details><summary>Example: (Click to expand) Changing the default client token_endpoint_auth_method.</summary><br>


To change the default client token_endpoint_auth_method, configure `clientDefaults` to be an object like so:
  

```js
{
  token_endpoint_auth_method: 'client_secret_post'
}
```
</details>
<a id="client-defaults-changing-the-default-client-response-type-to-code-id-token"></a><details><summary>Example: (Click to expand) Changing the default client response type to `code id_token`.</summary><br>


To change the default client response_types, configure `clientDefaults` to be an object like so:
  

```js
{
  response_types: ['code id_token'],
  grant_types: ['authorization_code', 'implicit'],
}
```
</details>

---

### clockTolerance

Specifies the maximum acceptable clock skew tolerance (in seconds) for validating time-sensitive operations, including JWT validation for Request Objects, DPoP Proofs, and other timestamp-based security mechanisms.   
  

_**recommendation**_: This value should be kept as small as possible while accommodating expected clock drift between the authorization server and client systems.  


_**default value**_:
```js
15
```

---

### conformIdTokenClaims

ID Token only contains End-User claims when the requested `response_type` is `id_token`  

[`OIDC Core 1.0` - Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ScopeClaims) defines that claims requested using the `scope` parameter are only returned from the UserInfo Endpoint unless the `response_type` is `id_token`.   
 Despite this configuration, the ID Token always includes claims requested using the `scope` parameter when the userinfo endpoint is disabled, or when issuing an Access Token not applicable for access to the userinfo endpoint.   
  


_**default value**_:
```js
true
```

---

### cookies

Configuration for HTTP cookies used to maintain User-Agent state throughout the authorization flow. These settings conform to the [cookies module interface specification](https://github.com/pillarjs/cookies/tree/0.9.1?tab=readme-ov-file#cookiessetname--values--options). The `maxAge` and `expires` properties are ignored; cookie lifetimes are instead controlled via the `ttl.Session` and `ttl.Interaction` configuration parameters.  


---

### cookies.long

Options for long-term cookies.  


_**default value**_:
```js
{
  httpOnly: true,
  sameSite: 'lax'
}
```

---

### cookies.names

Specifies the HTTP cookie names used for state management during the authorization flow.  


_**default value**_:
```js
{
  interaction: '_interaction',
  resume: '_interaction_resume',
  session: '_session'
}
```

---

### cookies.short

Options for short-term cookies.  


_**default value**_:
```js
{
  httpOnly: true,
  sameSite: 'lax'
}
```

---

### discovery

Pass additional properties to this object to extend the discovery document.  


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

---

### enableHttpPostMethods

Specifies whether HTTP POST method support shall be enabled at the Authorization Endpoint and the Logout Endpoint (if enabled). When enabled, the authorization server shall accept POST requests at these endpoints in addition to the standard GET requests. This configuration may only be used when the `cookies.long.sameSite` configuration value is `none`.  


_**default value**_:
```js
false
```

---

### expiresWithSession

Specifies a helper function that shall be invoked to determine whether authorization codes, device codes, or authorization-endpoint-returned opaque access tokens shall be bound to the end-user session. When session binding is enabled, this policy shall be applied to all opaque tokens issued from the authorization code, device code, or subsequent refresh token exchanges. When artifacts are session-bound, their originating session will be loaded by its unique identifier every time the artifacts are encountered. Session-bound artifacts shall be effectively revoked when the end-user logs out, providing automatic cleanup of token state upon session termination.  


_**default value**_:
```js
async function expiresWithSession(ctx, code) {
  return !code.scopes.has('offline_access');
}
```

---

### extraClientMetadata

Specifies the configuration for custom client metadata properties that shall be supported by the authorization server for client registration and metadata validation purposes. This configuration enables extension of standard OAuth 2.0 and OpenID Connect client metadata with deployment-specific properties. Existing standards-defined properties are snakeCased on a Client instance (e.g. `client.redirectUris`), while new properties defined by this configuration shall be available with their names verbatim (e.g. `client['urn:example:client:my-property']`).  


---

### extraClientMetadata.properties

Specifies an array of property names that clients shall be allowed to have defined within their client metadata during registration and management operations. Each property name listed here extends the standard client metadata schema according to authorization server policy.  


_**default value**_:
```js
[]
```

---

### extraClientMetadata.validator

Specifies a validator function that shall be executed in order once for every property defined in `extraClientMetadata.properties`, regardless of its value or presence in the client metadata passed during registration or update operations. The function MUST be synchronous; async validators or functions returning Promise shall be rejected during runtime. To modify the current client metadata values (for the current key or any other) simply modify the passed in `metadata` argument within the validator function.  


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
}
```

---

### extraParams

Specifies additional parameters that shall be recognized by the authorization, device authorization, backchannel authentication, and pushed authorization request endpoints. These extended parameters become available in `ctx.oidc.params` and are passed to interaction session details for processing.   
 This configuration accepts either an iterable object (array or Set of strings) for simple parameter registration, or a plain object with string properties representing parameter names and values being validation functions (synchronous or asynchronous) for the corresponding parameter values.   
 Parameter validators are executed regardless of the parameter's presence or value, enabling validation of parameter presence as well as assignment of default values. When the value is `null` or `undefined`, the parameter is registered without validation constraints.   
 Note: These validators execute during the final phase of the request validation process. Modifications to other parameters (such as assigning default values) will not trigger re-validation of the entire request.   
  


_**default value**_:
```js
[]
```
<a id="extra-params-registering-an-extra-origin-parameter-with-its-validator"></a><details><summary>Example: (Click to expand) Registering an extra `origin` parameter with its validator.</summary><br>

```js
import { errors } from 'oidc-provider';
const extraParams = {
  async origin(ctx, value, client) {
    // @param ctx - koa request context
    // @param value - the `origin` parameter value (string or undefined)
    // @param client - client making the request
    if (hasDefaultOrigin(client)) {
      // assign default
      ctx.oidc.params.origin ||= value ||= getDefaultOrigin(client);
    }
    if (!value && requiresOrigin(ctx, client)) {
      // reject when missing but required
      throw new errors.InvalidRequest('"origin" is required for this request')
    }
    if (!allowedOrigin(value, client)) {
      // reject when not allowed
      throw new errors.InvalidRequest('requested "origin" is not allowed for this client')
    }
  }
}
```
</details>

---

### extraTokenClaims

Specifies a helper function that shall be invoked to add additional claims to Access Tokens during the token issuance process. For opaque Access Tokens, the returned claims shall be stored in the authorization server storage under the `extra` property and shall be returned by the introspection endpoint as top-level claims. For JWT-formatted Access Tokens, the returned claims shall be included as top-level claims within the JWT payload. Claims returned by this function will not overwrite pre-existing top-level claims in the token.   
  


_**default value**_:
```js
async function extraTokenClaims(ctx, token) {
  return undefined;
}
```
<a id="extra-token-claims-to-add-an-arbitrary-claim-to-an-access-token"></a><details><summary>Example: (Click to expand) To add an arbitrary claim to an Access Token.</summary><br>

```js
{
  async extraTokenClaims(ctx, token) {
    return {
      'urn:idp:example:foo': 'bar',
    };
  }
}
```
</details>

---

### fetch

Specifies a function that shall be invoked whenever the authorization server needs to make calls to external HTTPS resources. The interface and expected return value shall conform to the [Fetch API specification](https://fetch.spec.whatwg.org/) [`fetch()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/fetch) standard. The default implementation uses a timeout of 2500ms and does not send a user-agent header.   
  


_**default value**_:
```js
function fetch(url, options) {
  options.signal = AbortSignal.timeout(2500);
  options.headers = new Headers(options.headers);
  options.headers.set('user-agent', ''); // removes the user-agent header in Node's global fetch()
 
  return globalThis.fetch(url, options);
}
```
<a id="fetch-to-change-the-request's-timeout"></a><details><summary>Example: (Click to expand) To change the request's timeout.</summary><br>


To change all request's timeout configure the fetch as a function like so:
  

```js
 {
   fetch(url, options) {
     options.signal = AbortSignal.timeout(5000);
     return globalThis.fetch(url, options);
   }
 }
```
</details>

---

### formats.bitsOfOpaqueRandomness

Specifies the entropy configuration for opaque token generation. The value shall be an integer (or a function returning an integer) that determines the cryptographic strength of generated opaque tokens. The resulting opaque token length shall be calculated as `Math.ceil(i / Math.log2(n))` where `i` is the specified bit count and `n` is the number of symbols in the encoding alphabet (64 characters in the base64url character set used by this implementation).   
  


_**default value**_:
```js
256
```
<a id="formats-bits-of-opaque-randomness-to-have-e-g-refresh-tokens-values-longer-than-access-tokens"></a><details><summary>Example: (Click to expand) To have e.g. Refresh Tokens values longer than Access Tokens.</summary><br>

```js
function bitsOfOpaqueRandomness(ctx, token) {
  if (token.kind === 'RefreshToken') {
    return 384;
  }
  return 256;
}
```
</details>

---

### formats.customizers

Specifies customizer functions that shall be invoked immediately before issuing structured Access Tokens to enable modification of token headers and payload claims according to authorization server policy. These functions shall be called during the token formatting process to apply deployment-specific customizations to the token structure before signing.   
  


_**default value**_:
```js
{
  jwt: undefined
}
```
<a id="formats-customizers-to-push-additional-headers-and-payload-claims-to-a-jwt-format-access-token"></a><details><summary>Example: (Click to expand) To push additional headers and payload claims to a `jwt` format Access Token.</summary><br>

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

---

### interactions

Specifies the configuration for interaction policy and end-user redirection that shall be applied to determine that user interaction is required during the authorization process. This configuration enables customization of authentication and consent flows according to deployment-specific requirements.   
  


---

### interactions.policy

Specifies the structure of Prompts and their associated checks that shall be applied during authorization request processing. The policy is formed by Prompt and Check class instances that define the conditions under which user interaction is required. The default policy implementation provides a fresh instance that can be customized, and the relevant classes are exported for configuration purposes.   
  


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
      ...(oidc.params.login_hint === undefined
        ? undefined
        : { login_hint: oidc.params.login_hint }),
      ...(oidc.params.id_token_hint === undefined
        ? undefined
        : { id_token_hint: oidc.params.id_token_hint }),
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

  new Check(
    'id_token_hint',
    'id_token_hint and authenticated subject do not match',
    async (ctx) => {
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
        sub = await instance(oidc.provider).configuration.pairwiseIdentifier(
          ctx,
          sub,
          oidc.client,
        );
      }

      if (payload.sub !== sub) {
        return Check.REQUEST_PROMPT;
      }

      return Check.NO_NEED_TO_PROMPT;
    },
  ),

  new Check(
    'claims_id_token_sub_value',
    'requested subject could not be obtained',
    async (ctx) => {
      const { oidc } = ctx;

      if (
        !oidc.claims.id_token
          || !oidc.claims.id_token.sub
          || !('value' in oidc.claims.id_token.sub)
      ) {
        return Check.NO_NEED_TO_PROMPT;
      }

      let sub = oidc.session.accountId;
      if (sub === undefined) {
        return Check.REQUEST_PROMPT;
      }

      if (oidc.client.subjectType === 'pairwise') {
        sub = await instance(oidc.provider).configuration.pairwiseIdentifier(
          ctx,
          sub,
          oidc.client,
        );
      }

      if (oidc.claims.id_token.sub.value !== sub) {
        return Check.REQUEST_PROMPT;
      }

      return Check.NO_NEED_TO_PROMPT;
    },
    ({ oidc }) => ({ sub: oidc.claims.id_token.sub }),
  ),

  new Check(
    'essential_acrs',
    'none of the requested ACRs could not be obtained',
    (ctx) => {
      const { oidc } = ctx;
      const request = oidc.claims?.id_token?.acr ?? {};

      if (!request?.essential || !request?.values) {
        return Check.NO_NEED_TO_PROMPT;
      }

      if (!Array.isArray(oidc.claims.id_token.acr.values)) {
        throw new errors.InvalidRequest('invalid claims.id_token.acr.values type');
      }

      if (request.values.includes(oidc.acr)) {
        return Check.NO_NEED_TO_PROMPT;
      }

      return Check.REQUEST_PROMPT;
    },
    ({ oidc }) => ({ acr: oidc.claims.id_token.acr }),
  ),

  new Check(
    'essential_acr',
    'requested ACR could not be obtained',
    (ctx) => {
      const { oidc } = ctx;
      const request = oidc.claims?.id_token?.acr ?? {};

      if (!request?.essential || !request?.value) {
        return Check.NO_NEED_TO_PROMPT;
      }

      if (request.value === oidc.acr) {
        return Check.NO_NEED_TO_PROMPT;
      }

      return Check.REQUEST_PROMPT;
    },
    ({ oidc }) => ({ acr: oidc.claims.id_token.acr }),
  ),
)

/* CONSENT PROMPT */
new Prompt(
  { name: 'consent', requestable: true },

  new Check('native_client_prompt', 'native clients require End-User interaction', 'interaction_required', (ctx) => {
    const { oidc } = ctx;
    if (
      oidc.client.applicationType === 'native'
      && oidc.params.response_type !== 'none'
      && (!oidc.result?.consent)
    ) {
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }),

  new Check('op_scopes_missing', 'requested scopes not granted', (ctx) => {
    const { oidc } = ctx;
    const encounteredScopes = new Set(oidc.grant.getOIDCScopeEncountered().split(' '));

    let missing;
    for (const scope of oidc.requestParamOIDCScopes) {
      if (!encounteredScopes.has(scope)) {
        missing ||= [];
        missing.push(scope);
      }
    }

    if (missing?.length) {
      ctx.oidc[missingOIDCScope] = missing;
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }, ({ oidc }) => ({ missingOIDCScope: oidc[missingOIDCScope] })),

  new Check('op_claims_missing', 'requested claims not granted', (ctx) => {
    const { oidc } = ctx;
    const encounteredClaims = new Set(oidc.grant.getOIDCClaimsEncountered());

    let missing;
    for (const claim of oidc.requestParamClaims) {
      if (!encounteredClaims.has(claim) && !['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim)) {
        missing ||= [];
        missing.push(claim);
      }
    }

    if (missing?.length) {
      ctx.oidc[missingOIDCClaims] = missing;
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }, ({ oidc }) => ({ missingOIDCClaims: oidc[missingOIDCClaims] })),

  // checks resource server scopes
  new Check('rs_scopes_missing', 'requested scopes not granted', (ctx) => {
    const { oidc } = ctx;

    let missing;

    for (const [indicator, resourceServer] of Object.entries(ctx.oidc.resourceServers)) {
      const encounteredScopes = new Set(oidc.grant.getResourceScopeEncountered(indicator).split(' '));
      const requestedScopes = ctx.oidc.requestParamScopes;
      const availableScopes = resourceServer.scopes;

      for (const scope of requestedScopes) {
        if (availableScopes.has(scope) && !encounteredScopes.has(scope)) {
          missing ||= {};
          missing[indicator] ||= [];
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

  // checks authorization_details
  new Check('rar_prompt', 'authorization_details were requested', (ctx) => {
    const { oidc } = ctx;

    if (oidc.params.authorization_details && !oidc.result?.consent) {
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }, ({ oidc }) => ({ rar: JSON.parse(oidc.params.authorization_details) })),
)
]
```
<a id="interactions-policy-default-interaction-policy-description"></a><details><summary>Example: (Click to expand) default interaction policy description.</summary><br>


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
<a id="interactions-policy-disabling-default-consent-checks"></a><details><summary>Example: (Click to expand) disabling default consent checks.</summary><br>


You may be required to skip (silently accept) some of the consent checks, while it is discouraged there are valid reasons to do that, for instance in some first-party scenarios or going with pre-existing, previously granted, consents. To simply silenty "accept" first-party/resource indicated scopes or pre-agreed-upon claims use the `loadExistingGrant` configuration helper function, in there you may just instantiate (and save!) a grant for the current clientId and accountId values.  


</details>
<a id="interactions-policy-modifying-the-default-interaction-policy"></a><details><summary>Example: (Click to expand) modifying the default interaction policy.</summary><br>

```js
import { interactionPolicy } from 'oidc-provider';
const { Prompt, Check, base } = interactionPolicy;
const basePolicy = base()
// basePolicy.get(name) => returns a Prompt instance by its name
// basePolicy.remove(name) => removes a Prompt instance by its name
// basePolicy.add(prompt, index) => adds a Prompt instance to a specific index, default is add the prompt as the last one
// prompt.checks.get(reason) => returns a Check instance by its reason
// prompt.checks.remove(reason) => removes a Check instance by its reason
// prompt.checks.add(check, index) => adds a Check instance to a specific index, default is add the check as the last one
```
</details>

---

### interactions.url

Specifies a function that shall be invoked to determine the destination URL for redirecting the User-Agent when user interaction is required during authorization processing. This function enables customization of the interaction endpoint location and may return both absolute and relative URLs according to deployment requirements.  


_**default value**_:
```js
async function interactionsUrl(ctx, interaction) {
  return `/interaction/${interaction.uid}`;
}
```

---

### issueRefreshToken

Specifies a helper function that shall be invoked to determine whether a refresh token shall be issued during token endpoint operations. This function enables policy-based control over refresh token issuance according to authorization server requirements, client capabilities, and granted scope values.   
  


_**default value**_:
```js
async function issueRefreshToken(ctx, client, code) {
  return (
    client.grantTypeAllowed('refresh_token')
    && code.scopes.has('offline_access')
  );
}
```
<a id="issue-refresh-token-to-always-issue-a-refresh-token-cont"></a><details><summary>Example: (Click to expand) To always issue a refresh token (cont.)</summary><br>


(cont.) if a client has the grant allowed and scope includes offline_access or the client is a public web client doing code flow. Configure `issueRefreshToken` like so
  

```js
async issueRefreshToken(ctx, client, code) {
  if (!client.grantTypeAllowed('refresh_token')) {
    return false;
  }
  return code.scopes.has('offline_access') || (client.applicationType === 'web' && client.clientAuthMethod === 'none');
}
```
</details>

---

### loadExistingGrant

Helper function invoked to load existing authorization grants that may be used to resolve an Authorization Request without requiring additional end-user interaction. The default implementation attempts to load grants based on the interaction result's `consent.grantId` property, falling back to the existing grantId for the requesting client in the current session.  


_**default value**_:
```js
async function loadExistingGrant(ctx) {
  const grantId = ctx.oidc.result?.consent?.grantId
    || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);
  if (grantId) {
    return ctx.oidc.provider.Grant.find(grantId);
  }
  return undefined;
}
```

---

### pairwiseIdentifier

Specifies a helper function that shall be invoked to generate pairwise subject identifier values for ID Tokens and UserInfo responses, as specified in OpenID Connect Core 1.0. This function enables privacy-preserving subject identifier generation that provides unique identifiers per client while maintaining consistent identification for the same end-user across requests to the same client.   
  

_**recommendation**_: Implementations should employ memoization or caching mechanisms when this function may be invoked multiple times with identical arguments within a single request.  


_**default value**_:
```js
async function pairwiseIdentifier(ctx, accountId, client) {
  return crypto
    .createHash('sha256')
    .update(client.sectorIdentifier)
    .update(accountId)
    .update(os.hostname()) // put your own unique salt here, or implement other mechanism
    .digest('hex');
}
```

---

### pkce

[`RFC7636`](https://www.rfc-editor.org/rfc/rfc7636.html) - Proof Key for Code Exchange (`PKCE`)  

`PKCE` configuration such as policy check on the required use of `PKCE`.   
  


---

### pkce.required

Configures if and when the authorization server requires clients to use `PKCE`. This helper is called whenever an authorization request lacks the code_challenge parameter. Return:
 - `false` to allow the request to continue without `PKCE`
 - `true` to abort the request  


_**default value**_:
```js
function pkceRequired(ctx, client) {
  // All public clients MUST use PKCE as per
  // https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1-2.1
  if (client.clientAuthMethod === 'none') {
    return true;
  }
  const fapiProfile = ctx.oidc.isFapi('2.0', '1.0 Final');
  // FAPI 2.0 as per
  // https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2-2.5
  if (fapiProfile === '2.0') {
    return true;
  }
  // FAPI 1.0 Advanced as per
  // https://openid.net/specs/openid-financial-api-part-2-1_0-final.html#authorization-server
  if (fapiProfile === '1.0 Final' && ctx.oidc.route === 'pushed_authorization_request') {
    return true;
  }
  // In all other cases use of PKCE is RECOMMENDED as per
  // https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1-2.2
  // but the server doesn't force them to.
  return false;
}
```

---

### renderError

Specifies a function that shall be invoked to present error responses to the User-Agent during authorization server operations. This function enables customization of error presentation according to deployment-specific user interface requirements.  


_**default value**_:
```js
async function renderError(ctx, out, error) {
  ctx.type = 'html';
  ctx.body = `<!DOCTYPE html>
    <html>
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

---

### responseTypes

Specifies the response_type values supported by this authorization server. In accordance with RFC 9700 (OAuth 2.0 Security Best Current Practice), the default configuration excludes response types that result in access tokens being issued directly by the authorization endpoint.   
  


_**default value**_:
```js
[
  'code id_token',
  'code',
  'id_token',
  'none'
]
```
<a id="response-types-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>


These are values defined in [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#Authentication) and [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0-final.html)
  

```js
[
  'code',
  'id_token', 'id_token token',
  'code id_token', 'code token', 'code id_token token',
  'none',
]
```
</details>

---

### revokeGrantPolicy

Specifies a helper function that shall be invoked to determine whether an underlying Grant entry shall be revoked in addition to the specific token or code being processed. This function enables enforcement of grant revocation policies according to authorization server security requirements. The function is invoked in the following contexts:
 - RP-Initiated Logout
 - Opaque Access Token Revocation
 - Refresh Token Revocation
 - Authorization Code re-use
 - Device Code re-use
 - Backchannel Authentication Request re-use
 - Rotated Refresh Token re-use  


_**default value**_:
```js
function revokeGrantPolicy(ctx) {
  if (ctx.oidc.route === 'revocation' && ctx.oidc.entities.AccessToken) {
    return false;
  }
  return true;
}
```

---

### rotateRefreshToken

Specifies the refresh token rotation policy that shall be applied by the authorization server when refresh tokens are used. This configuration determines whether and under what conditions refresh tokens shall be rotated. Supported values include:
 - `false` - refresh tokens shall not be rotated and their initial expiration date is final
 - `true` - refresh tokens shall be rotated when used, with the current token marked as consumed and a new one issued with new TTL; when a consumed refresh token is encountered an error shall be returned and the whole token chain (grant) is revoked
 - `function` - a function returning true/false that shall be invoked to determine whether rotation should occur based on request context and authorization server policy   
 <br/><br/>   
 The default configuration value implements a sensible refresh token rotation policy that:
 - only allows refresh tokens to be rotated (have their TTL prolonged by issuing a new one) for one year
 - otherwise always rotates public client tokens that are not sender-constrained
 - otherwise only rotates tokens if they're being used close to their expiration (>= 70% TTL passed)  


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
  if (
    client.clientAuthMethod === 'none'
    && !refreshToken.isSenderConstrained()
  ) {
    return true;
  }
  // rotate if the token is nearing expiration (it's beyond 70% of its lifetime)
  return refreshToken.ttlPercentagePassed() >= 70;
}
```

---

### routes

Defines the URL path mappings for authorization server endpoints. All route values are relative and shall begin with a forward slash ("/") character.  


_**default value**_:
```js
{
  authorization: '/auth',
  backchannel_authentication: '/backchannel',
  challenge: '/challenge',
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

---

### scopes

Specifies additional OAuth 2.0 scope values that this authorization server shall support and advertise in its discovery document. Resource Server-specific scopes shall be configured via the `features.resourceIndicators` mechanism.  


_**default value**_:
```js
[
  'openid',
  'offline_access'
]
```

---

### sectorIdentifierUriValidate

Specifies a function that shall be invoked to determine whether the sectorIdentifierUri of a client being loaded, registered, or updated should be fetched and its contents validated against the client metadata.  


_**default value**_:
```js
function sectorIdentifierUriValidate(client) {
  // @param client - the Client instance
  return true;
}
```

---

### subjectTypes

Specifies the array of Subject Identifier types that this authorization server shall support for end-user identification purposes. When only `pairwise` is supported, it shall become the default `subject_type` client metadata value. Supported identifier types shall include:
 - `public` - provides the same subject identifier value to all clients
 - `pairwise` - provides a unique subject identifier value per client to enhance privacy  


_**default value**_:
```js
[
  'public'
]
```

---

### ttl

Specifies the Time-To-Live (TTL) values that shall be applied to various artifacts within the authorization server. TTL values may be specified as either a numeric value (in seconds) or a synchronous function that returns a numeric value based on the current request context and authorization server policy.   
  

_**recommendation**_: Token TTL values should be set to the minimum duration necessary for the intended use case to minimize security exposure.  

_**recommendation**_: For refresh tokens requiring extended lifetimes, consider utilizing the `rotateRefreshToken` configuration option, which extends effective token lifetime through rotation rather than extended initial TTL values.  


_**default value**_:
```js
{
  AccessToken: function AccessTokenTTL(ctx, token, client) {
    return token.resourceServer?.accessTokenTTL || 60 * 60; // 1 hour in seconds
  },
  AuthorizationCode: 60 /* 1 minute in seconds */,
  BackchannelAuthenticationRequest: function BackchannelAuthenticationRequestTTL(ctx, request, client) {
    if (ctx?.oidc?.params.requested_expiry) {
      return Math.min(10 * 60, +ctx.oidc.params.requested_expiry); // 10 minutes in seconds or requested_expiry, whichever is shorter
    }
  
    return 10 * 60; // 10 minutes in seconds
  },
  ClientCredentials: function ClientCredentialsTTL(ctx, token, client) {
    return token.resourceServer?.accessTokenTTL || 10 * 60; // 10 minutes in seconds
  },
  DeviceCode: 600 /* 10 minutes in seconds */,
  Grant: 1209600 /* 14 days in seconds */,
  IdToken: 3600 /* 1 hour in seconds */,
  Interaction: 3600 /* 1 hour in seconds */,
  RefreshToken: function RefreshTokenTTL(ctx, token, client) {
    if (
      ctx?.oidc?.entities.RotatedRefreshToken
      && client.applicationType === 'web'
      && client.clientAuthMethod === 'none'
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
<a id="ttl-to-resolve-a-ttl-on-runtime-for-each-new-token"></a><details><summary>Example: (Click to expand) To resolve a ttl on runtime for each new token.</summary><br>


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

---

### enabledJWA

Specifies the JSON Web Algorithm (JWA) values supported by this authorization server for various cryptographic operations, as defined in RFC 7518 and related specifications.  


---

### enabledJWA.attestSigningAlgValues

JWS "alg" Algorithm values the authorization server supports to verify signed Client Attestation and Client Attestation PoP JWTs with   
  


_**default value**_:
```js
[
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-attest-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
]
```
</details>

---

### enabledJWA.authorizationEncryptionAlgValues

JWE "alg" Algorithm values the authorization server supports for JWT Authorization response (`JARM`) encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'dir'
]
```
<a id="enabled-jwa-authorization-encryption-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // direct encryption
  'dir',
]
```
</details>

---

### enabledJWA.authorizationEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt JWT Authorization Responses (`JARM`) with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-authorization-encryption-enc-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

---

### enabledJWA.authorizationSigningAlgValues

JWS "alg" Algorithm values the authorization server supports to sign JWT Authorization Responses (`JARM`) with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-authorization-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>

---

### enabledJWA.clientAuthSigningAlgValues

JWS "alg" Algorithm values the authorization server supports for signed JWT Client Authentication (`private_key_jwt` and `client_secret_jwt`)   
  


_**default value**_:
```js
[
  'HS256',
  'RS256',
  'PS256',
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-client-auth-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>

---

### enabledJWA.dPoPSigningAlgValues

JWS "alg" Algorithm values the authorization server supports to verify signed DPoP proof JWTs with   
  


_**default value**_:
```js
[
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-d-po-p-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
]
```
</details>

---

### enabledJWA.idTokenEncryptionAlgValues

JWE "alg" Algorithm values the authorization server supports for ID Token encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'dir'
]
```
<a id="enabled-jwa-id-token-encryption-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // direct encryption
  'dir',
]
```
</details>

---

### enabledJWA.idTokenEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt ID Tokens with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-id-token-encryption-enc-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

---

### enabledJWA.idTokenSigningAlgValues

JWS "alg" Algorithm values the authorization server supports to sign ID Tokens with.   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-id-token-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>

---

### enabledJWA.introspectionEncryptionAlgValues

JWE "alg" Algorithm values the authorization server supports for JWT Introspection response encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'dir'
]
```
<a id="enabled-jwa-introspection-encryption-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // direct encryption
  'dir',
]
```
</details>

---

### enabledJWA.introspectionEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt JWT Introspection responses with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-introspection-encryption-enc-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

---

### enabledJWA.introspectionSigningAlgValues

JWS "alg" Algorithm values the authorization server supports to sign JWT Introspection responses with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-introspection-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>

---

### enabledJWA.requestObjectEncryptionAlgValues

JWE "alg" Algorithm values the authorization server supports to receive encrypted Request Objects (`JAR`) with   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'dir'
]
```
<a id="enabled-jwa-request-object-encryption-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // direct encryption
  'dir',
]
```
</details>

---

### enabledJWA.requestObjectEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the authorization server supports to decrypt Request Objects (`JAR`) with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-request-object-encryption-enc-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

---

### enabledJWA.requestObjectSigningAlgValues

JWS "alg" Algorithm values the authorization server supports to receive signed Request Objects (`JAR`) with   
  


_**default value**_:
```js
[
  'HS256',
  'RS256',
  'PS256',
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-request-object-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>

---

### enabledJWA.userinfoEncryptionAlgValues

JWE "alg" Algorithm values the authorization server supports for UserInfo Response encryption   
  


_**default value**_:
```js
[
  'A128KW',
  'A256KW',
  'ECDH-ES',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'dir'
]
```
<a id="enabled-jwa-userinfo-encryption-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  // asymmetric RSAES based
  'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
  // asymmetric ECDH-ES based
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric AES key wrapping
  'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
  // direct encryption
  'dir',
]
```
</details>

---

### enabledJWA.userinfoEncryptionEncValues

JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt UserInfo responses with   
  


_**default value**_:
```js
[
  'A128CBC-HS256',
  'A128GCM',
  'A256CBC-HS512',
  'A256GCM'
]
```
<a id="enabled-jwa-userinfo-encryption-enc-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
]
```
</details>

---

### enabledJWA.userinfoSigningAlgValues

JWS "alg" Algorithm values the authorization server supports to sign UserInfo responses with   
  


_**default value**_:
```js
[
  'RS256',
  'PS256',
  'ES256',
  'Ed25519',
  'EdDSA'
]
```
<a id="enabled-jwa-userinfo-signing-alg-values-supported-values-list"></a><details><summary>Example: (Click to expand) Supported values list.</summary><br>

```js
[
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'EdDSA',
  'HS256', 'HS384', 'HS512',
]
```
</details>
<!-- END CONF OPTIONS -->

## FAQ

### ID Token does not include claims other than sub

Only response types that do not end up with an access_token (so, response_type=id_token) have
end-user claims other than `sub` in their ID Tokens. This is the
[Core 1.0](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ScopeClaims) spec behaviour. Read
it you'll see requesting claims through the scope parameter only adds these claims to userinfo
unless the response_type is `id_token` in which case they're added there. All other response types
have access to the userinfo endpoint which returns these scope-requested claims. The other option is
to allow clients to request specific claims from a source they expect it in via the `claims`
parameter.

But, if you absolutely need to have scope-requested claims in ID Tokens you can use the
[`conformIdTokenClaims`](#conformidtokenclaims) configuration option.

### Why does my .well-known/openid-configuration link to http endpoints instead of https endpoints?

Your authorization server is behind a TLS terminating proxy, tell your Provider instance to trust the proxy
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
const client_id = "an:identifier";
const client_secret = "some secure & non-standard secret";

// After formencoding these two tokens
const encoded_id = "an%3Aidentifier";
const encoded_secret = "some+secure+%26+non%2Dstandard+secret";

// Basic auth header format Authorization: Basic base64(encoded_id + ':' + encoded_secret)
// Authorization: Basic YW4lM0FpZGVudGlmaWVyOnNvbWUrc2VjdXJlKyUyNitub24lMkRzdGFuZGFyZCtzZWNyZXQ=
```

So essentially, your client is not submitting the client auth in a conform way and you should fix
that.

### I'm getting a client authentication failed error with no details

Every client is configured with one of 7 available
[`token_endpoint_auth_method` values](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method)
and it must adhere to how that given method must be submitted. Submitting multiple means of
authentication is also not possible. Authorization server operators are encouraged to set up
listeners for errors
(see [events.md](https://github.com/panva/node-oidc-provider/blob/v9.x/docs/events.md)) and
deliver them to client developers out-of-band, e.g. by logs in an admin interface.

```js
function handleClientAuthErrors({ headers: { authorization }, oidc: { body, client } }, err) {
  if (err.statusCode === 401 && err.message === "invalid_client") {
    // console.log(err);
    // save error details out-of-bands for the client developers, `authorization`, `body`, `client`
    // are just some details available, you can dig in ctx object for more.
  }
}
provider.on("grant.error", handleClientAuthErrors);
provider.on("introspection.error", handleClientAuthErrors);
provider.on("revocation.error", handleClientAuthErrors);
```

### Refresh Tokens

> I'm not getting refresh_token from token_endpoint grant_type=authorization_code responses, why?

Do you support offline_access scope and consent prompt? Did the client request them in the
authentication request?

> Yeah, still no refresh_token

Does the client have grant_type=refresh_token configured?

> Aaaah, that was it. (or one of the above if you follow [Core 1.0#OfflineAccess](http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess))

---

> The Authorization Server MAY grant Refresh Tokens in other contexts that are beyond the scope of this specification. How about that?

Yeah, yeah, see [configuration](#issuerefreshtoken)

### Password Grant Type, ROPC

If you need it today something's wrong!

- https://www.youtube.com/watch?v=qMtYaDmhnHU
- https://www.youtube.com/watch?v=zuVuhl_Axbs

ROPC falls beyond the scope of what the library can do magically on its own having only accountId
and the claims, it does not ask for an interface necessary to find an account by a username nor by
validating the password digest. Custom implementation using the provided
[`registerGrantType`](#custom-grant-types) API is simple enough if ROPC is absolutely required.

### How to display, on the website of the authorization server itself, if the user is signed-in or not

```js
const ctx = provider.createContext(req, res);
const session = await provider.Session.get(ctx);
const signedIn = !!session.accountId;
```

### Client Credentials only clients

The `redirect_uris is mandatory property` error occurs but Client Credential clients
don't need `redirect_uris` or `response_types`... This error appears
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

The `redirect_uris is mandatory property` error occurs but the resource server needs
none. This error appears because they are required properties, but they can be empty...

```js
{
  // ... rest of the client configuration
  redirect_uris: [],
  response_types: [],
  grant_types: []
}
```

[support-sponsor]: https://github.com/sponsors/panva
[sponsor-auth0]: https://a0.to/signup/panva
