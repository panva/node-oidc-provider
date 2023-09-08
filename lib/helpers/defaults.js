/* eslint-disable no-shadow */
/* eslint-disable no-unused-vars */

import * as crypto from 'node:crypto';
import * as util from 'node:util';
import * as os from 'node:os';

import MemoryAdapter from '../adapters/memory_adapter.js';
import { DEV_KEYSTORE } from '../consts/index.js';

import * as base64url from './base64url.js';
import * as attention from './attention.js';
import nanoid from './nanoid.js';
import { base as defaultPolicy } from './interaction_policy/index.js';
import htmlSafe from './html_safe.js';
import * as errors from './errors.js';

const randomFill = util.promisify(crypto.randomFill);

const warned = new Set();
function shouldChange(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    attention.info(`default ${name} function called, you SHOULD change it in order to ${msg}.`);
  }
}
function mustChange(name, msg) {
  if (!warned.has(name)) {
    warned.add(name);
    attention.warn(`default ${name} function called, you MUST change it in order to ${msg}.`);
  }
}

function clientBasedCORS(ctx, origin, client) {
  mustChange('clientBasedCORS', 'control CORS allowed Origins based on the client making a CORS request');
  return false;
}

function getCertificate(ctx) {
  mustChange('features.mTLS.getCertificate', 'retrieve the PEM-formatted client certificate from the request context');
  throw new Error('features.mTLS.getCertificate function not configured');
}

function certificateAuthorized(ctx) {
  mustChange('features.mTLS.certificateAuthorized', 'determine if the client certificate is verified and comes from a trusted CA');
  throw new Error('features.mTLS.certificateAuthorized function not configured');
}

function certificateSubjectMatches(ctx, property, expected) {
  mustChange('features.mTLS.certificateSubjectMatches', 'verify that the tls_client_auth_* registered client property value matches the certificate one');
  throw new Error('features.mTLS.certificateSubjectMatches function not configured');
}

function deviceInfo(ctx) {
  return {
    ip: ctx.ip,
    ua: ctx.get('user-agent'),
  };
}

async function userCodeInputSource(ctx, form, out, err) {
  // @param ctx - koa request context
  // @param form - form source (id="op.deviceInputForm") to be embedded in the page and submitted
  //   by the End-User.
  // @param out - if an error is returned the out object contains details that are fit to be
  //   rendered, i.e. does not include internal error messages
  // @param err - error object with an optional userCode property passed when the form is being
  //   re-rendered due to code missing/invalid/expired
  shouldChange('features.deviceFlow.userCodeInputSource', 'customize the look of the user code input page');
  let msg;
  if (err && (err.userCode || err.name === 'NoCodeError')) {
    msg = '<p class="red">The code you entered is incorrect. Try again</p>';
  } else if (err && err.name === 'AbortedError') {
    msg = '<p class="red">The Sign-in request was interrupted</p>';
  } else if (err) {
    msg = '<p class="red">There was an error processing your request</p>';
  } else {
    msg = '<p>Enter the code displayed on your device</p>';
  }
  ctx.body = `<!DOCTYPE html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Sign-in</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <meta http-equiv="x-ua-compatible" content="ie=edge">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}p.red{color:#d50000}input[type=email],input[type=password],input[type=text]{height:44px;font-size:16px;width:100%;margin-bottom:10px;-webkit-appearance:none;background:#fff;border:1px solid #d9d9d9;border-top:1px solid silver;padding:0 8px;box-sizing:border-box;-moz-box-sizing:border-box}[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative;text-align:center;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}[type=submit]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}input[type=text]{text-transform:uppercase;text-align: center}input[type=text]::placeholder{text-transform: none}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Sign-in</h1>
        ${msg}
        ${form}
        <button type="submit" form="op.deviceInputForm">Continue</button>
      </div>
    </body>
    </html>`;
}

function requireNonce(ctx) {
  return false;
}

async function userCodeConfirmSource(ctx, form, client, deviceInfo, userCode) {
  // @param ctx - koa request context
  // @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
  //   submitted by the End-User.
  // @param deviceInfo - device information from the device_authorization_endpoint call
  // @param userCode - formatted user code by the configured mask
  shouldChange('features.deviceFlow.userCodeConfirmSource', 'customize the look of the user code confirmation page');
  const {
    clientId, clientName, clientUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client;
  ctx.body = `<!DOCTYPE html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Device Login Confirmation</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);.help,h1,h1+p{text-align:center}h1,h1+p{font-weight:100}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#f7f7f7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}button[autofocus]{width:100%;display:block;margin-bottom:10px;position:relative;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button[autofocus]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}button[name=abort]{background:0 0!important;border:none;padding:0!important;font:inherit;cursor:pointer}a,button[name=abort]{text-decoration:none;color:#666;font-weight:400;display:inline-block;opacity:.6}.help{width:100%;font-size:12px}code{font-size:2em}
      </style>
    </head>
    <body>
      <div class="container">
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
        <div class="help">
          <button type="submit" form="op.deviceConfirmForm" value="yes" name="abort">[ Abort ]</button>
        </div>
      </div>
    </body>
    </html>`;
}

async function successSource(ctx) {
  // @param ctx - koa request context
  shouldChange('features.deviceFlow.successSource', 'customize the look of the device code success page');
  const {
    clientId, clientName, clientUri, initiateLoginUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client;
  ctx.body = `<!DOCTYPE html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Sign-in Success</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Sign-in Success</h1>
        <p>Your sign-in ${clientName ? `with ${clientName}` : ''} was successful, you can now close this page.</p>
      </div>
    </body>
    </html>`;
}

async function introspectionAllowedPolicy(ctx, client, token) {
  shouldChange('features.introspection.allowedPolicy', 'to check whether the caller is authorized to receive the introspection response');

  if (client.clientAuthMethod === 'none' && token.clientId !== ctx.oidc.client.clientId) {
    return false;
  }

  return true;
}

function idFactory(ctx) {
  return nanoid();
}

async function secretFactory(ctx) {
  const bytes = Buffer.allocUnsafe(64);
  await randomFill(bytes);
  return base64url.encodeBuffer(bytes);
}

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

async function useGrantedResource(ctx, model) {
  // @param ctx - koa request context
  // @param model - depending on the request's grant_type this can be either an AuthorizationCode, BackchannelAuthenticationRequest,
  //                RefreshToken, or DeviceCode model instance.
  return false;
}

async function getResourceServerInfo(ctx, resourceIndicator, client) {
  // @param ctx - koa request context
  // @param resourceIndicator - resource indicator value either requested or resolved by the defaultResource helper.
  // @param client - client making the request
  mustChange('features.resourceIndicators.getResourceServerInfo', 'to provide details about the Resource Server identified by the Resource Indicator');
  throw new errors.InvalidTarget();
}

async function extraTokenClaims(ctx, token) {
  return undefined;
}

function httpOptions(url) {
  return {
    signal: undefined, // defaults to AbortSignal.timeout(2500)
    agent: undefined, // defaults to node's global agents (https.globalAgent or http.globalAgent)
    dnsLookup: undefined, // defaults to `dns.lookup()` (https://nodejs.org/api/dns.html#dnslookuphostname-options-callback)
    'user-agent': undefined, // defaults to not sending the user-agent HTTP header
  };
}

async function expiresWithSession(ctx, code) {
  return !code.scopes.has('offline_access');
}

async function issueRefreshToken(ctx, client, code) {
  return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
}

function pkceRequired(ctx, client) {
  return true;
}

async function pairwiseIdentifier(ctx, accountId, client) {
  mustChange('pairwiseIdentifier', 'provide an implementation for pairwise identifiers, the default one uses `os.hostname()` as salt and is therefore not fit for anything else than development');
  return crypto.createHash('sha256')
    .update(client.sectorIdentifier)
    .update(accountId)
    .update(os.hostname()) // put your own unique salt here, or implement other mechanism
    .digest('hex');
}

function AccessTokenTTL(ctx, token, client) {
  shouldChange('ttl.AccessToken', 'define the expiration for AccessToken artifacts');
  return token.resourceServer?.accessTokenTTL || 60 * 60; // 1 hour in seconds
}

function AuthorizationCodeTTL(ctx, code, client) {
  return 60; // 1 minute in seconds
}

function ClientCredentialsTTL(ctx, token, client) {
  shouldChange('ttl.ClientCredentials', 'define the expiration for ClientCredentials artifacts');
  return token.resourceServer?.accessTokenTTL || 10 * 60; // 10 minutes in seconds
}

function DeviceCodeTTL(ctx, deviceCode, client) {
  shouldChange('ttl.DeviceCode', 'define the expiration for DeviceCode artifacts');
  return 10 * 60; // 10 minutes in seconds
}

function BackchannelAuthenticationRequestTTL(ctx, request, client) {
  shouldChange('ttl.BackchannelAuthenticationRequest', 'define the expiration for BackchannelAuthenticationRequest artifacts');
  if (ctx?.oidc && ctx.oidc.params.requested_expiry) {
    return Math.min(10 * 60, +ctx.oidc.params.requested_expiry); // 10 minutes in seconds or requested_expiry, whichever is shorter
  }

  return 10 * 60; // 10 minutes in seconds
}

function IdTokenTTL(ctx, token, client) {
  shouldChange('ttl.IdToken', 'define the expiration for IdToken artifacts');
  return 60 * 60; // 1 hour in seconds
}

function RefreshTokenTTL(ctx, token, client) {
  shouldChange('ttl.RefreshToken', 'define the expiration for RefreshToken artifacts');
  if (
    ctx && ctx.oidc.entities.RotatedRefreshToken
    && client.applicationType === 'web'
    && client.clientAuthMethod === 'none'
    && !token.isSenderConstrained()
  ) {
    // Non-Sender Constrained SPA RefreshTokens do not have infinite expiration through rotation
    return ctx.oidc.entities.RotatedRefreshToken.remainingTTL;
  }

  return 14 * 24 * 60 * 60; // 14 days in seconds
}

function InteractionTTL(ctx, interaction) {
  shouldChange('ttl.Interaction', 'define the expiration for Interaction artifacts');
  return 60 * 60; // 1 hour in seconds
}

function SessionTTL(ctx, session) {
  shouldChange('ttl.Session', 'define the expiration for Session artifacts');
  return 14 * 24 * 60 * 60; // 14 days in seconds
}

function GrantTTL(ctx, grant, client) {
  shouldChange('ttl.Grant', 'define the expiration for Grant artifacts');
  return 14 * 24 * 60 * 60; // 14 days in seconds
}

function extraClientMetadataValidator(ctx, key, value, metadata) {
  // @param ctx - koa request context (only provided when a client is being constructed during
  //              Client Registration Request or Client Update Request
  // @param key - the client metadata property name
  // @param value - the property value
  // @param metadata - the current accumulated client metadata
  // @param ctx - koa request context (only provided when a client is being constructed during
  //              Client Registration Request or Client Update Request

  // validations for key, value, other related metadata

  // throw new errors.InvalidClientMetadata() to reject the client metadata

  // metadata[key] = value; to (re)assign metadata values

  // return not necessary, metadata is already a reference
}

async function postLogoutSuccessSource(ctx) {
  // @param ctx - koa request context
  shouldChange('features.rpInitiatedLogout.postLogoutSuccessSource', 'customize the look of the default post logout success page');
  const {
    clientId, clientName, clientUri, initiateLoginUri, logoUri, policyUri, tosUri,
  } = ctx.oidc.client || {}; // client is defined if the user chose to stay logged in with the OP
  const display = clientName || clientId;
  ctx.body = `<!DOCTYPE html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Sign-out Success</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Sign-out Success</h1>
        <p>Your sign-out ${display ? `with ${display}` : ''} was successful.</p>
      </div>
    </body>
    </html>`;
}

async function logoutSource(ctx, form) {
  // @param ctx - koa request context
  // @param form - form source (id="op.logoutForm") to be embedded in the page and submitted by
  //   the End-User
  shouldChange('features.rpInitiatedLogout.logoutSource', 'customize the look of the logout page');
  ctx.body = `<!DOCTYPE html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Logout Request</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);button,h1{text-align:center}h1{font-weight:100;font-size:1.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}button{font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;width:100%;display:block;margin-bottom:10px;position:relative;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Do you want to sign-out from ${ctx.host}?</h1>
        ${form}
        <button autofocus type="submit" form="op.logoutForm" value="yes" name="logout">Yes, sign me out</button>
        <button type="submit" form="op.logoutForm">No, stay signed in</button>
      </div>
    </body>
    </html>`;
}

async function renderError(ctx, out, error) {
  shouldChange('renderError', 'customize the look of the error page');
  ctx.type = 'html';
  ctx.body = `<!DOCTYPE html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>oops! something went wrong</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1{font-weight:100;text-align:center;font-size:2.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}pre{white-space:pre-wrap;white-space:-moz-pre-wrap;white-space:-pre-wrap;white-space:-o-pre-wrap;word-wrap:break-word;margin:0 0 0 1em;text-indent:-1em}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>oops! something went wrong</h1>
        ${Object.entries(out).map(([key, value]) => `<pre><strong>${key}</strong>: ${htmlSafe(value)}</pre>`).join('')}
      </div>
    </body>
    </html>`;
}

async function interactionsUrl(ctx, interaction) {
  return `/interaction/${interaction.uid}`;
}

async function findAccount(ctx, sub, token) {
  // @param ctx - koa request context
  // @param sub {string} - account identifier (subject)
  // @param token - is a reference to the token used for which a given account is being loaded,
  //   is undefined in scenarios where claims are returned from authorization endpoint
  mustChange('findAccount', 'use your own account model');
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

function rotateRefreshToken(ctx) {
  const { RefreshToken: refreshToken, Client: client } = ctx.oidc.entities;

  // cap the maximum amount of time a refresh token can be
  // rotated for up to 1 year, afterwards its TTL is final
  if (refreshToken.totalLifetime() >= 365.25 * 24 * 60 * 60) {
    return false;
  }

  // rotate non sender-constrained public client refresh tokens
  if (client.clientAuthMethod === 'none' && !refreshToken.isSenderConstrained()) {
    return true;
  }

  // rotate if the token is nearing expiration (it's beyond 70% of its lifetime)
  return refreshToken.ttlPercentagePassed() >= 70;
}

async function loadExistingGrant(ctx) {
  const grantId = (ctx.oidc.result?.consent?.grantId)
    || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);

  if (grantId) {
    return ctx.oidc.provider.Grant.find(grantId);
  }
  return undefined;
}

function revokeGrantPolicy(ctx) {
  return true;
}

function sectorIdentifierUriValidate(client) {
  // @param client - the Client instance
  return true;
}

async function processLoginHintToken(ctx, loginHintToken) {
  // @param ctx - koa request context
  // @param loginHintToken - string value of the login_hint_token parameter
  mustChange('features.ciba.processLoginHintToken', 'process the login_hint_token parameter and return the accountId value to use for processsing the request');
  throw new Error('features.ciba.processLoginHintToken not implemented');
}

async function processLoginHint(ctx, loginHint) {
  // @param ctx - koa request context
  // @param loginHint - string value of the login_hint parameter
  mustChange('features.ciba.processLoginHint', 'process the login_hint parameter and return the accountId value to use for processsing the request');
  throw new Error('features.ciba.processLoginHint not implemented');
}

async function verifyUserCode(ctx, account, userCode) {
  // @param ctx - koa request context
  // @param account -
  // @param userCode - string value of the user_code parameter, when not provided it is undefined
  mustChange('features.ciba.verifyUserCode', 'verify the user_code parameter is present when required and verify its value');
  throw new Error('features.ciba.verifyUserCode not implemented');
}

async function validateBindingMessage(ctx, bindingMessage) {
  // @param ctx - koa request context
  // @param bindingMessage - string value of the binding_message parameter, when not provided it is undefined
  shouldChange('features.ciba.validateBindingMessage', 'verify the binding_message parameter is present when required and verify its value');
  if (bindingMessage && !/^[a-zA-Z0-9-._+/!?#]{1,20}$/.exec(bindingMessage)) {
    throw new errors.InvalidBindingMessage('the binding_message value, when provided, needs to be 1 - 20 characters in length and use only a basic set of characters (matching the regex: ^[a-zA-Z0-9-._+/!?#]{1,20}$ )');
  }
}

async function validateRequestContext(ctx, requestContext) {
  // @param ctx - koa request context
  // @param requestContext - string value of the request_context parameter, when not provided it is undefined
  mustChange('features.ciba.validateRequestContext', 'verify the request_context parameter is present when required and verify its value');
  throw new Error('features.ciba.validateRequestContext not implemented');
}

async function triggerAuthenticationDevice(ctx, request, account, client) {
  // @param ctx - koa request context
  // @param request - the BackchannelAuthenticationRequest instance
  // @param account - the account object retrieved by findAccount
  // @param client - the Client instance
  mustChange('features.ciba.triggerAuthenticationDevice', "to trigger the authentication and authorization process on end-user's Authentication Device");
  throw new Error('features.ciba.triggerAuthenticationDevice not implemented');
}

function makeDefaults() {
  const defaults = {

    /*
     * acrValues
     *
     * description: Array of strings, the Authentication Context Class References that the OP supports.
     */
    acrValues: [],

    /*
     * adapter
     *
     * description: The provided example and any new instance of oidc-provider will use the basic
     * in-memory adapter for storing issued tokens, codes, user sessions, dynamically registered
     * clients, etc. This is fine as long as you develop, configure and generally just play around
     * since every time you restart your process all information will be lost. As soon as you cannot
     * live with this limitation you will be required to provide your own custom adapter constructor
     * for oidc-provider to use. This constructor will be called for every model accessed the first
     * time it is needed.
     * The API oidc-provider expects is documented [here](/example/my_adapter.js).
     *
     * example: MongoDB adapter implementation
     *
     * See [/example/adapters/mongodb.js](/example/adapters/mongodb.js)
     *
     * example: Redis adapter implementation
     *
     * See [/example/adapters/redis.js](/example/adapters/redis.js)
     *
     * example: Redis w/ ReJSON adapter implementation
     *
     * See [/example/adapters/redis_rejson.js](/example/adapters/redis_rejson.js)
     *
     * example: Default in-memory adapter implementation
     *
     * See [/lib/adapters/memory_adapter.js](/lib/adapters/memory_adapter.js)
     *
     * @nodefault
     */
    adapter: MemoryAdapter,

    /*
     * claims
     *
     * description: Describes the claims that the OpenID Provider MAY be able to supply values for.
     *
     * It is used to achieve two different things related to claims:
     * - which additional claims are available to RPs (configure as `{ claimName: null }`)
     * - which claims fall under what scope (configure `{ scopeName: ['claim', 'another-claim'] }`)
     *
     * example: OpenID Connect 1.0 Standard Claims
     *
     * See [/recipes/claim_configuration.md](/recipes/claim_configuration.md)
     *
     */
    claims: {
      acr: null, sid: null, auth_time: null, iss: null, openid: ['sub'],
    },

    /*
     * clientBasedCORS
     *
     * description: Function used to check whether a given CORS request should be allowed
     *   based on the request's client.
     *
     * example: Client Metadata-based CORS Origin allow list
     *
     * See [/recipes/client_based_origins.md](/recipes/client_based_origins.md)
     */
    clientBasedCORS,

    /*
     * clients
     *
     * description: Array of objects representing client metadata. These clients are referred to as
     * static, they don't expire, never reload, are always available. In addition to these
     * clients the provider will use your adapter's `find` method when a non-static client_id is
     * encountered. If you only wish to support statically configured clients and
     * no dynamic registration then make it so that your adapter resolves client find calls with a
     * falsy value (e.g. `return Promise.resolve()`) and don't take unnecessary DB trips.
     *
     * Client's metadata is validated as defined by the respective specification they've been defined
     * in.
     *
     * example: Available Metadata
     *
     * application_type, client_id, client_name, client_secret, client_uri, contacts,
     * default_acr_values, default_max_age, grant_types, id_token_signed_response_alg,
     * initiate_login_uri, jwks, jwks_uri, logo_uri, policy_uri, post_logout_redirect_uris,
     * redirect_uris, require_auth_time, response_types, scope, sector_identifier_uri, subject_type,
     * token_endpoint_auth_method, tos_uri, userinfo_signed_response_alg
     *
     * <br/><br/>The following metadata is available but may not be recognized depending on your
     * provider's configuration.<br/><br/>
     *
     * authorization_encrypted_response_alg, authorization_encrypted_response_enc,
     * authorization_signed_response_alg, backchannel_logout_session_required, backchannel_logout_uri,
     * id_token_encrypted_response_alg,
     * id_token_encrypted_response_enc, introspection_encrypted_response_alg,
     * introspection_encrypted_response_enc, introspection_signed_response_alg,
     * request_object_encryption_alg, request_object_encryption_enc, request_object_signing_alg,
     * request_uris,
     * tls_client_auth_san_dns, tls_client_auth_san_email, tls_client_auth_san_ip,
     * tls_client_auth_san_uri, tls_client_auth_subject_dn,
     * tls_client_certificate_bound_access_tokens, token_endpoint_auth_signing_alg,
     * userinfo_encrypted_response_alg, userinfo_encrypted_response_enc, web_message_uris
     *
     */
    clients: [],

    /*
     * clientDefaults
     *
     * description: Default client metadata to be assigned when unspecified by the client metadata,
     * e.g. during Dynamic Client Registration or for statically configured clients. The default value
     * does not represent all default values, but merely copies its subset. You can provide any used
     * client metadata property in this object.
     *
     * example: Changing the default client token_endpoint_auth_method
     *
     * To change the default client token_endpoint_auth_method configure `clientDefaults` to be an
     * object like so:
     *
     * ```js
     * {
     *   token_endpoint_auth_method: 'client_secret_post'
     * }
     * ```
     * example: Changing the default client response type to `code id_token`
     *
     * To change the default client response_types configure `clientDefaults` to be an
     * object like so:
     *
     * ```js
     * {
     *   response_types: ['code id_token'],
     *   grant_types: ['authorization_code', 'implicit'],
     * }
     * ```
     *
     */
    clientDefaults: {
      grant_types: ['authorization_code'],
      id_token_signed_response_alg: 'RS256',
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    },

    /*
     * clockTolerance
     *
     * description: A `Number` value (in seconds) describing the allowed system clock skew for
     *   validating client-provided JWTs, e.g. Request Objects, DPoP Proofs and otherwise comparing
     *   timestamps
     * recommendation: Only set this to a reasonable value when needed to cover server-side client and
     *   oidc-provider server clock skew.
     */
    clockTolerance: 15,

    /*
     * conformIdTokenClaims
     *
     * title: ID Token only contains End-User claims when the requested `response_type` is `id_token`
     *
     * description: [`OIDC Core 1.0` - Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
     * defines that claims requested using the `scope` parameter are only returned from the UserInfo
     * Endpoint unless the `response_type` is `id_token`.
     *
     * Despite of this configuration the ID Token always includes claims requested using the `scope`
     * parameter when the userinfo endpoint is disabled, or when issuing an Access Token not applicable
     * for access to the userinfo endpoint.
     *
     */
    conformIdTokenClaims: true,

    /*
     * loadExistingGrant
     *
     * description: Helper function used to load existing but also just in time pre-established Grants
     * to attempt to resolve an Authorization Request with. Default: loads a grant based on the
     * interaction result `consent.grantId` first, falls back to the existing grantId for the client
     * in the current session.
     */
    loadExistingGrant,

    /*
     * allowOmittingSingleRegisteredRedirectUri
     *
     * title: Allow omitting the redirect_uri parameter when only a single one is registered for a client.
     */
    allowOmittingSingleRegisteredRedirectUri: true,

    /*
     * acceptQueryParamAccessTokens
     *
     * description: Several OAuth 2.0 / OIDC profiles prohibit the use of query strings to carry
     * access tokens. This setting either allows (true) or prohibits (false) that mechanism to be
     * used.
     *
     */
    acceptQueryParamAccessTokens: false,

    /*
     * cookies
     *
     * description: Options for the [cookie module](https://github.com/pillarjs/cookies#cookiesset-name--value---options--)
     *   used to keep track of various User-Agent states. The options `maxAge` and `expires` are ignored. Use `ttl.Session`
     *   and `ttl.Interaction` to configure the ttl and in turn the cookie expiration values for Session and Interaction
     *   models.
     * @nodefault
     */
    cookies: {
      /*
       * cookies.names
       *
       * description: Cookie names used to store and transfer various states.
       */
      names: {
        session: '_session', // used for main session reference
        interaction: '_interaction', // used by the interactions for interaction session reference
        resume: '_interaction_resume', // used when interactions resume authorization for interaction session reference
      },

      /*
       * cookies.long
       *
       * description: Options for long-term cookies
       * recommendation: set cookies.keys and cookies.long.signed = true
       */
      long: {
        httpOnly: true, // cookies are not readable by client-side javascript
        overwrite: true,
        sameSite: 'none',
      },

      /*
       * cookies.short
       *
       * description: Options for short-term cookies
       * recommendation: set cookies.keys and cookies.short.signed = true
       */
      short: {
        httpOnly: true, // cookies are not readable by client-side javascript
        overwrite: true,
        sameSite: 'lax',
      },

      /*
       * cookies.keys
       *
       * description: [Keygrip](https://www.npmjs.com/package/keygrip) Signing keys used for cookie
       *   signing to prevent tampering.
       * recommendation: Rotate regularly (by prepending new keys) with a reasonable interval and keep
       *   a reasonable history of keys to allow for returning user session cookies to still be valid
       *   and re-signed
       */
      keys: [],
    },

    /*
     * discovery
     *
     * description: Pass additional properties to this object to extend the discovery document
     */
    discovery: {
      claim_types_supported: ['normal'],
      claims_locales_supported: undefined,
      display_values_supported: undefined,
      op_policy_uri: undefined,
      op_tos_uri: undefined,
      service_documentation: undefined,
      ui_locales_supported: undefined,
    },

    /*
     * extraParams
     *
     * description: Pass an iterable object (i.e. array or Set of strings) to extend the parameters
     *   recognised by the authorization, device authorization, and pushed authorization request
     *   endpoints. These parameters are then available in `ctx.oidc.params` as well as passed to
     *   interaction session details.
     */
    extraParams: [],

    /*
     * features
     * description: Enable/disable features. Some features are still either based on draft or
     *   experimental RFCs. Enabling those will produce a warning in your console and you must
     *   be aware that breaking changes may occur between draft implementations and that those
     *   will be published as minor versions of oidc-provider. See the example below on how to
     *   acknowledge the specification is a draft (this will remove the warning log) and ensure
     *   the provider instance will fail to instantiate if a new version of oidc-provider bundles
     *   newer version of the RFC with breaking changes in it.
     *
     * example: Acknowledging a draft / experimental feature
     *
     * ```js
     * new Provider('http://localhost:3000', {
     *   features: {
     *     backchannelLogout: {
     *       enabled: true,
     *     },
     *   },
     * });
     *
     * // The above code produces this NOTICE
     * // NOTICE: The following draft features are enabled and their implemented version not acknowledged
     * // NOTICE:   - OpenID Connect Back-Channel Logout 1.0 - draft 06 (OIDF AB/Connect Working Group draft. URL: https://openid.net/specs/openid-connect-backchannel-1_0-06.html)
     * // NOTICE: Breaking changes between draft version updates may occur and these will be published as MINOR semver oidc-provider updates.
     * // NOTICE: You may disable this notice and these potentially breaking updates by acknowledging the current draft version. See https://github.com/panva/node-oidc-provider/tree/v7.3.0/docs/README.md#features
     *
     * new Provider('http://localhost:3000', {
     *   features: {
     *     backchannelLogout: {
     *       enabled: true,
     *       ack: 'draft-06', // < we're acknowledging draft 06 of the RFC
     *     },
     *   },
     * });
     * // No more NOTICE, at this point if the draft implementation changed to 07 and contained no breaking
     * // changes, you're good to go, still no NOTICE, your code is safe to run.
     *
     * // Now lets assume you upgrade oidc-provider version and it bundles draft 08 and it contains breaking
     * // changes
     * new Provider('http://localhost:3000', {
     *   features: {
     *     backchannelLogout: {
     *       enabled: true,
     *       ack: 'draft-06', // < bundled is draft-08, but we're still acknowledging draft-06
     *     },
     *   },
     * });
     * // Thrown:
     * // Error: An unacknowledged version of a draft feature is included in this oidc-provider version.
     * ```
     * @nodefault
     */
    features: {
      /*
       * features.devInteractions
       *
       * description: Development-ONLY out of the box interaction views bundled with the library allow
       * you to skip the boring frontend part while experimenting with oidc-provider. Enter any
       * username (will be used as sub claim value) and any password to proceed.
       *
       * Be sure to disable and replace this feature with your actual frontend flows and End-User
       * authentication flows as soon as possible. These views are not meant to ever be seen by actual
       * users.
       */
      devInteractions: { enabled: true },

      /*
       * features.dPoP
       *
       * title: [`RFC9449`](https://www.rfc-editor.org/rfc/rfc9449.html) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (`DPoP`)
       *
       * description: Enables `DPoP` - mechanism for sender-constraining tokens via a
       * proof-of-possession mechanism on the application level. Browser DPoP proof generation
       * [here](https://www.npmjs.com/package/dpop).
       */
      dPoP: {
        enabled: false,
        ack: undefined,
        /**
         * features.dPoP.nonceSecret
         *
         * description: A secret value used for generating server-provided DPoP nonces.
         * Must be a 32-byte length Buffer instance when provided.
         */
        nonceSecret: undefined,
        /**
         * features.dPoP.requireNonce
         *
         * description: Function used to determine whether a DPoP nonce is required or not.
         */
        requireNonce,
      },

      /*
       * features.backchannelLogout
       *
       * title: [`OIDC Back-Channel Logout 1.0`](https://openid.net/specs/openid-connect-backchannel-1_0-final.html)
       *
       * description: Enables Back-Channel Logout features.
       */
      backchannelLogout: { enabled: false },

      /*
       * features.ciba
       *
       * title: [OIDC Client Initiated Backchannel Authentication Flow (`CIBA`)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)
       *
       * description: Enables Core `CIBA` Flow, when combined with `features.fapi` and `features.requestObjects.request` enables [Financial-grade API: Client Initiated Backchannel Authentication Profile - Implementer's Draft 01](https://openid.net/specs/openid-financial-api-ciba-ID1.html) as well.
       *
       */
      ciba: {
        enabled: false,

        /*
         * features.ciba.deliveryModes
         *
         * description: Fine-tune the supported token delivery modes. Supported values are
         *   - `poll`
         *   - `ping`
         *
         */
        deliveryModes: ['poll'],

        /*
         * features.ciba.triggerAuthenticationDevice
         *
         * description: Helper function used to trigger the authentication and authorization on end-user's Authentication Device. It is called after
         * accepting the backchannel authentication request but before sending client back the response.
         *
         * When the end-user authenticates use `provider.backchannelResult()` to finish the Consumption Device login process.
         *
         * example: `provider.backchannelResult()` method
         *
         * `backchannelResult` is a method on the Provider prototype, it returns a `Promise` with no fulfillment value.
         *
         * ```js
         * const provider = new Provider(...);
         * await provider.backchannelResult(...);
         * ```
         *
         * `backchannelResult(request, result[, options]);`
         * - `request` BackchannelAuthenticationRequest - BackchannelAuthenticationRequest instance.
         * - `result` Grant | OIDCProviderError - instance of a persisted Grant model or an OIDCProviderError (all exported by errors).
         * - `options.acr?`: string - Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied.
         * - `options.amr?`: string[] - Identifiers for authentication methods used in the authentication.
         * - `options.authTime?`: number - Time when the End-User authentication occurred.
         *
         */
        triggerAuthenticationDevice,

        /*
         * features.ciba.validateBindingMessage
         *
         * description: Helper function used to process the binding_message parameter and throw if its not following the authorization server's policy.
         *
         * recommendation: Use `throw new errors.InvalidBindingMessage('validation error message')` when the binding_message is invalid.
         * recommendation: Use `return undefined` when a binding_message isn't required and wasn't provided.
         *
         */
        validateBindingMessage,

        /*
         * features.ciba.validateRequestContext
         *
         * description: Helper function used to process the request_context parameter and throw if its not following the authorization server's policy.
         *
         * recommendation: Use `throw new errors.InvalidRequest('validation error message')` when the request_context is required by policy and missing or
         * invalid.
         * recommendation: Use `return undefined` when a request_context isn't required and wasn't provided.
         *
         */
        validateRequestContext,

        /*
         * features.ciba.processLoginHintToken
         *
         * description: Helper function used to process the login_hint_token parameter and return the accountId value to use for processsing the request.
         *
         * recommendation: Use `throw new errors.ExpiredLoginHintToken('validation error message')` when login_hint_token is expired.
         * recommendation: Use `throw new errors.InvalidRequest('validation error message')` when login_hint_token is invalid.
         * recommendation: Use `return undefined` or when you can't determine the accountId from the login_hint.
         *
         */
        processLoginHintToken,

        /*
         * features.ciba.processLoginHint
         *
         * description: Helper function used to process the login_hint parameter and return the accountId value to use for processsing the request.
         *
         * recommendation: Use `throw new errors.InvalidRequest('validation error message')` when login_hint is invalid.
         * recommendation: Use `return undefined` or when you can't determine the accountId from the login_hint.
         *
         */
        processLoginHint,

        /*
         * features.ciba.verifyUserCode
         *
         * description: Helper function used to verify the user_code parameter value is present when required and verify its value.
         *
         * recommendation: Use `throw new errors.MissingUserCode('validation error message')` when user_code should have been provided but wasn't.
         * recommendation: Use `throw new errors.InvalidUserCode('validation error message')` when the provided user_code is invalid.
         * recommendation: Use `return undefined` when no user_code was provided and isn't required.
         *
         */
        verifyUserCode,
      },

      /*
       * features.mTLS
       *
       * title: [`RFC8705`](https://www.rfc-editor.org/rfc/rfc8705.html) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens (`MTLS`)
       *
       * description: Enables specific features from the Mutual TLS specification. The three main
       * features have their own specific setting in this feature's configuration object and
       * you must provide functions for resolving some of the functions which are deployment-specific.
       *
       */
      mTLS: {
        enabled: false,

        /*
         * features.mTLS.certificateBoundAccessTokens
         *
         * description: Enables section 3 & 4 Mutual TLS Client Certificate-Bound Tokens by exposing
         * the client's `tls_client_certificate_bound_access_tokens` metadata property.
         */
        certificateBoundAccessTokens: false,

        /*
         * features.mTLS.selfSignedTlsClientAuth
         *
         * description: Enables section 2.2. Self-Signed Certificate Mutual TLS client authentication
         *   method `self_signed_tls_client_auth` for use in the server's `clientAuthMethods`
         *   configuration.
         */
        selfSignedTlsClientAuth: false,

        /*
         * features.mTLS.tlsClientAuth
         *
         * description: Enables section 2.1. PKI Mutual TLS client authentication method
         *   `tls_client_auth` for use in the server's `clientAuthMethods`
         *   configuration.
         */
        tlsClientAuth: false,

        /*
         * features.mTLS.getCertificate
         *
         * description: Function used to retrieve a `crypto.X509Certificate` instance,
         *   or a PEM-formatted string, representation of client certificate used in the request.
         */
        getCertificate,

        /*
         * features.mTLS.certificateAuthorized
         *
         * description: Function used to determine if the client certificate, used in the
         *   request, is verified and comes from a trusted CA for the client. Should return true/false.
         *   Only used for `tls_client_auth` client authentication method.
         */
        certificateAuthorized,

        /*
         * features.mTLS.certificateSubjectMatches
         *
         * description: Function used to determine if the client certificate, used in the
         *   request, subject matches the registered client property. Only used for `tls_client_auth`
         *   client authentication method.
         */
        certificateSubjectMatches,
      },

      /*
       * features.claimsParameter
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) - Requesting Claims using the "claims" Request Parameter
       *
       * description: Enables the use and validations of `claims` parameter as described in the
       * specification.
       *
       */
      claimsParameter: { enabled: false },

      /*
       * features.clientCredentials
       *
       * title: [`RFC6749`](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3.4) - Client Credentials
       *
       * description: Enables `grant_type=client_credentials` to be used on the token endpoint.
       */
      clientCredentials: { enabled: false },

      /*
       * features.deviceFlow
       *
       * title: [`RFC8628`](https://www.rfc-editor.org/rfc/rfc8628.html) - OAuth 2.0 Device Authorization Grant (`Device Flow`)
       *
       * description: Enables Device Authorization Grant
       */
      deviceFlow: {
        enabled: false,

        /*
         * features.deviceFlow.charset
         *
         * description: alias for a character set of the generated user codes. Supported values are
         *   - `base-20` uses BCDFGHJKLMNPQRSTVWXZ
         *   - `digits` uses 0123456789
         */
        charset: 'base-20',

        /*
         * features.deviceFlow.mask
         *
         * description: a string used as a template for the generated user codes, `*` characters will
         *   be replaced by random chars from the charset, `-`(dash) and ` ` (space) characters may be
         *   included for readability. See the RFC for details about minimal recommended entropy.
         */
        mask: '****-****',

        /*
         * features.deviceFlow.deviceInfo
         *
         * description: Function used to extract details from the device authorization endpoint
         *   request. This is then available during the end-user confirm screen and is supposed to
         *   aid the user confirm that the particular authorization initiated by the user from a
         *   device in their possession.
         */
        deviceInfo,
        /*
         * features.deviceFlow.userCodeInputSource
         *
         * description: HTML source rendered when device code feature renders an input prompt for the
         *   User-Agent.
         */
        userCodeInputSource,

        /*
         * features.deviceFlow.userCodeConfirmSource
         *
         * description: HTML source rendered when device code feature renders an a confirmation prompt for
         *   ther User-Agent.
         */
        userCodeConfirmSource,

        /*
         * features.deviceFlow.successSource
         *
         * description: HTML source rendered when device code feature renders a success page for the
         *   User-Agent.
         */
        successSource,
      },

      /*
       * features.encryption
       *
       * description: Enables encryption features such as receiving encrypted UserInfo responses,
       * encrypted ID Tokens and allow receiving encrypted Request Objects.
       */
      encryption: { enabled: false },

      /*
       * features.fapi
       *
       * title: Financial-grade API Security Profile (`FAPI`)
       *
       * description: Enables extra Authorization Server behaviours defined in FAPI that cannot be
       * achieved by other configuration options.
       */
      fapi: {
        enabled: false,
        /*
         * features.fapi.profile
         *
         * description: The specific profile of `FAPI` to enable. Supported values are:
         *
         * - '1.0 Final' Enables behaviours from [Financial-grade API Security Profile 1.0 - Part 2: Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html)
         * - '1.0 ID2' Enables behaviours from [Financial-grade API - Part 2: Read and Write API Security Profile - Implementer's Draft 02](https://openid.net/specs/openid-financial-api-part-2-ID2.html)
         * - Function returning one of the other supported values, or undefined if `FAPI` behaviours are to be ignored. The function is invoked with two arguments `(ctx, client)` and serves the purpose of allowing the used profile to be context-specific.
         */
        profile: undefined,
      },

      /*
       * features.rpInitiatedLogout
       *
       * title: [`OIDC RP-Initiated Logout 1.0`](https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html)
       *
       * description: Enables RP-Initiated Logout features
       */
      rpInitiatedLogout: {
        enabled: true,

        /*
         * features.rpInitiatedLogout.postLogoutSuccessSource
         *
         * description: HTML source rendered when RP-Initiated Logout concludes a logout but there
         *   was no `post_logout_redirect_uri` provided by the client.
         */
        postLogoutSuccessSource,

        /*
         * features.rpInitiatedLogout.logoutSource
         *
         * description: HTML source rendered when RP-Initiated Logout renders a confirmation
         *   prompt for the User-Agent.
         */
        logoutSource,
      },

      /*
       * features.introspection
       *
       * title: [`RFC7662`](https://www.rfc-editor.org/rfc/rfc7662.html) - OAuth 2.0 Token Introspection
       *
       * description: Enables Token Introspection for:
       *   - opaque access tokens
       *   - refresh tokens
       *
       */
      introspection: {
        enabled: false,

        /*
         * features.introspection.allowedPolicy
         *
         * description: Helper function used to determine whether the client/RS (client argument)
         *   is allowed to introspect the given token (token argument).
         */
        allowedPolicy: introspectionAllowedPolicy,
      },

      /*
       * features.jwtIntrospection
       *
       * title: [draft-ietf-oauth-jwt-introspection-response-10](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-10) - JWT Response for OAuth Token Introspection
       *
       * description: Enables JWT responses for Token Introspection features
       *
       * recommendation: Updates to draft specification versions are released as MINOR library versions,
       * if you utilize these specification implementations consider using the tilde `~` operator
       * in your package.json since breaking changes may be introduced as part of these version
       * updates. Alternatively, [acknowledge](#features) the version and be notified of breaking
       * changes as part of your CI.
       */
      jwtIntrospection: { enabled: false, ack: undefined },

      /*
       * features.jwtResponseModes
       *
       * title: [JWT Secured Authorization Response Mode (`JARM`)](https://openid.net/specs/oauth-v2-jarm.html)
       *
       * description: Enables JWT Secured Authorization Responses
       */
      jwtResponseModes: { enabled: false },

      /*
       * features.pushedAuthorizationRequests
       *
       * title: [`RFC9126`](https://www.rfc-editor.org/rfc/rfc9126.html) - OAuth 2.0 Pushed Authorization Requests (`PAR`)
       *
       * description: Enables the use of `pushed_authorization_request_endpoint` defined by the Pushed
       * Authorization Requests RFC.
       */
      pushedAuthorizationRequests: {
        enabled: true,

        /*
         * features.pushedAuthorizationRequests.requirePushedAuthorizationRequests
         *
         * description: Makes the use of `PAR` required for all authorization
         * requests as an OP policy.
         */
        requirePushedAuthorizationRequests: false,
      },

      /*
       * features.registration
       *
       * title: [`Dynamic Client Registration 1.0`](https://openid.net/specs/openid-connect-registration-1_0.html) and [`RFC7591` - OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591.html)
       *
       * description: Enables Dynamic Client Registration.
       */
      registration: {
        enabled: false,

        /*
         * features.registration.initialAccessToken
         *
         * description: Enables registration_endpoint to check a valid initial access token is
         *   provided as a bearer token during the registration call. Supported types are
         *   - `string` the string value will be checked as a static initial access token
         *   - `boolean` true/false to enable/disable adapter backed initial access tokens
         *
         * example: To add an adapter backed initial access token and retrive its value
         *
         * ```js
         * new (provider.InitialAccessToken)({}).save().then(console.log);
         * ```
         */
        initialAccessToken: false,

        /*
         * features.registration.policies
         *
         * description: define registration and registration management policies applied to client
         *   properties. Policies are sync/async functions that are assigned to an Initial Access
         *   Token that run before the regular client property validations are run. Multiple policies
         *   may be assigned to an Initial Access Token and by default the same policies will transfer
         *   over to the Registration Access Token. A policy may throw / reject and it may modify the
         *   properties object.
         *
         * example: To define registration and registration management policies
         *
         * To define policy functions configure `features.registration` to be an object like so:
         * ```js
         * {
         *   enabled: true,
         *   initialAccessToken: true, // to enable adapter-backed initial access tokens
         *   policies: {
         *     'my-policy': function (ctx, properties) {
         *       // @param ctx - koa request context
         *       // @param properties - the client properties which are about to be validated
         *
         *       // example of setting a default
         *       if (!('client_name' in properties)) {
         *         properties.client_name = generateRandomClientName();
         *       }
         *
         *       // example of forcing a value
         *       properties.userinfo_signed_response_alg = 'RS256';
         *
         *       // example of throwing a validation error
         *       if (someCondition(ctx, properties)) {
         *         throw new errors.InvalidClientMetadata('validation error message');
         *       }
         *     },
         *     'my-policy-2': async function (ctx, properties) {},
         *   },
         * }
         * ```
         *
         * An Initial Access Token with those policies being executed (one by one in that order) is
         * created like so
         * ```js
         * new (provider.InitialAccessToken)({ policies: ['my-policy', 'my-policy-2'] }).save().then(console.log);
         * ```
         *
         * recommendation: referenced policies must always be present when encountered on a token, an AssertionError
         * will be thrown inside the request context if it is not, resulting in a 500 Server Error.
         *
         * recommendation: the same policies will be assigned to the Registration Access Token after a successful
         * validation. If you wish to assign different policies to the Registration Access Token
         * ```js
         * // inside your final ran policy
         * ctx.oidc.entities.RegistrationAccessToken.policies = ['update-policy'];
         * ```
         */
        policies: undefined,

        /*
         * features.registration.idFactory
         *
         * description: Function used to generate random client identifiers during dynamic
         *   client registration
         */
        idFactory,

        /*
         * features.registration.secretFactory
         *
         * description: Function used to generate random client secrets during dynamic
         *   client registration
         */
        secretFactory,

        /*
         * features.registration.issueRegistrationAccessToken
         *
         * description: Boolean or a function used to decide whether a registration access token will be
         * issued or not. Supported
         *   values are
         *   - `true` registration access tokens is issued
         *   - `false` registration access tokens is not issued
         *   - function returning true/false, true when token should be issued, false when it shouldn't
         *
         * example: To determine if a registration access token should be issued dynamically
         *
         * ```js
         * // @param ctx - koa request context
         * async issueRegistrationAccessToken(ctx) {
         *   return policyImplementation(ctx)
         * }
         * ```
         */
        issueRegistrationAccessToken: true,
      },

      /*
       * features.registrationManagement
       *
       * title: [OAuth 2.0 Dynamic Client Registration Management Protocol](https://www.rfc-editor.org/rfc/rfc7592.html)
       *
       * description: Enables Update and Delete features described in the RFC
       */
      registrationManagement: {
        enabled: false,

        /*
         * features.registrationManagement.rotateRegistrationAccessToken
         *
         * description: Enables registration access token rotation. The provider will discard the
         *   current Registration Access Token with a successful update and issue a new one, returning
         *   it to the client with the Registration Update Response. Supported
         *   values are
         *   - `false` registration access tokens are not rotated
         *   - `true` registration access tokens are rotated when used
         *   - function returning true/false, true when rotation should occur, false when it shouldn't
         * example: function use
         * ```js
         * {
         *   features: {
         *     registrationManagement: {
         *       enabled: true,
         *       async rotateRegistrationAccessToken(ctx) {
         *         // return tokenRecentlyRotated(ctx.oidc.entities.RegistrationAccessToken);
         *         // or
         *         // return customClientBasedPolicy(ctx.oidc.entities.Client);
         *       }
         *     }
         *   }
         * }
         * ```
         */
        rotateRegistrationAccessToken: true,
      },

      /*
       * features.resourceIndicators
       *
       * title: [`RFC8707`](https://www.rfc-editor.org/rfc/rfc8707.html) - Resource Indicators for OAuth 2.0
       *
       * description: Enables the use of `resource` parameter for the authorization and token
       *   endpoints to enable issuing Access Tokens for Resource Servers (APIs).
       *
       * - Multiple resource parameters may be present during Authorization Code Flow,
       * Device Authorization Grant, and Backchannel Authentication Requests,
       * but only a single audience for an Access Token is permitted.
       * - Authorization and Authentication Requests that result in an Access Token being issued by the
       * Authorization Endpoint must only contain a single resource (or one must be resolved using the
       * `defaultResource` helper).
       * - Client Credentials grant must only contain a single resource parameter.
       * - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request
       * exchanges, if the exchanged code/token does not include the `'openid'` scope and only has a single
       * resource then the resource parameter may be omitted - an Access Token for the single resource is
       * returned.
       * - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request
       * exchanges, if the exchanged code/token does not include the `'openid'` scope and has multiple
       * resources then the resource parameter must be provided (or one must be resolved using the
       * `defaultResource` helper).
       * An Access Token for the provided/resolved resource is returned.
       * - (with userinfo endpoint enabled and useGrantedResource helper returning falsy)
       * During Authorization Code / Refresh Token / Device Code
       * exchanges, if the exchanged code/token includes the `'openid'` scope and no resource
       * parameter is present - an Access Token for the UserInfo Endpoint is returned.
       * - (with userinfo endpoint enabled and useGrantedResource helper returning truthy)
       * During Authorization Code / Refresh Token / Device Code
       * exchanges, even if the exchanged code/token includes the `'openid'` scope and only has a single
       * resource then the resource parameter may be omitted - an Access Token for the single resource
       * is returned.
       * - (with userinfo endpoint disabled) During Authorization Code / Refresh Token / Device Code
       * exchanges, if the exchanged code/token includes the `'openid'` scope and only has a single
       * resource then the resource parameter may be omitted - an Access Token for the single resource
       * is returned.
       * - Issued Access Tokens always only contain scopes that are defined on the respective Resource
       * Server (returned from `features.resourceIndicators.getResourceServerInfo`).
       */
      resourceIndicators: {
        enabled: true,

        /*
         * features.resourceIndicators.defaultResource
         *
         * description: Function used to determine the default resource indicator for a request
         *   when none is provided by the client during the authorization request or when multiple
         *   are provided/resolved and only a single one is required during an Access Token Request.
         */
        defaultResource,

        /*
         * features.resourceIndicators.useGrantedResource
         *
         * description: Function used to determine if an already granted resource indicator
         *   should be used without being explicitly requested by the client during the Token Endpoint
         *   request.
         *
         * recommendation: Use `return true` when it's allowed for a client skip providing the "resource"
         *                 parameter at the Token Endpoint.
         * recommendation: Use `return false` (default) when it's required for a client to explitly
         *                 provide a "resource" parameter at the Token Endpoint or when other indication
         *                 dictates an Access Token for the UserInfo Endpoint should returned.
         */
        useGrantedResource,

        /*
         * features.resourceIndicators.getResourceServerInfo
         *
         * description: Function used to load information about a Resource Server (API) and check if the
         *   client is meant to request scopes for that particular resource.
         *
         * recommendation: Only allow client's pre-registered resource values, to pre-register these
         *   you shall use the `extraClientMetadata` configuration option to define a custom metadata
         *   and use that to implement your policy using this function.
         *
         * example: Resource Server (API) with two scopes, an expected audience value, an Access Token TTL and a JWT Access Token Format.
         * ```js
         * {
         *   scope: 'api:read api:write',
         *   audience: 'resource-server-audience-value',
         *   accessTokenTTL: 2 * 60 * 60, // 2 hours
         *   accessTokenFormat: 'jwt',
         *   jwt: {
         *     sign: { alg: 'ES256' },
         *   },
         * }
         * ```
         *
         * example: Resource Server (API) with two scopes and a symmetrically encrypted JWT Access Token Format.
         * ```js
         * {
         *   scope: 'api:read api:write',
         *   accessTokenFormat: 'jwt',
         *   jwt: {
         *     sign: false,
         *     encrypt: {
         *       alg: 'dir',
         *       enc: 'A128CBC-HS256',
         *       key: Buffer.from('f40dd9591646bebcb9c32aed02f5e610c2d15e1d38cde0c1fe14a55cf6bfe2d9', 'hex')
         *     },
         *   }
         * }
         * ```
         *
         * example: Resource Server Definition
         * ```js
         * {
         *   // REQUIRED
         *   // available scope values (space-delimited string)
         *   scope: string,
         *
         *   // OPTIONAL
         *   // "aud" (Audience) value to use
         *   // Default is the resource indicator value will be used as token audience
         *   audience?: string,
         *
         *   // OPTIONAL
         *   // Issued Token TTL
         *   // Default is - see `ttl` configuration
         *   accessTokenTTL?: number,
         *
         *   // Issued Token Format
         *   // Default is - opaque
         *   accessTokenFormat?: 'opaque' | 'jwt',
         *
         *   // JWT Access Token Format (when accessTokenFormat is 'jwt')
         *   // Default is `{ sign: { alg: 'RS256' }, encrypt: false }`
         *   // Tokens may be signed, signed and then encrypted, or just encrypted JWTs.
         *   jwt?: {
         *     // Tokens will be signed
         *     sign?:
         *      | {
         *          alg?: string, // 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES256K' | 'ES384' | 'ES512' | 'EdDSA' | 'RS256' | 'RS384' | 'RS512'
         *          kid?: string, // OPTIONAL `kid` to aid in signing key selection
         *        }
         *      | {
         *          alg: string, // 'HS256' | 'HS384' | 'HS512'
         *          key: crypto.KeyObject | Buffer, // shared symmetric secret to sign the JWT token with
         *          kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWS Header
         *        },
         *     // Tokens will be encrypted
         *     encrypt?: {
         *       alg: string, // 'dir' | 'RSA-OAEP' | 'RSA-OAEP-256' | 'RSA-OAEP-384' | 'RSA-OAEP-512' | 'ECDH-ES' | 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW' | 'A128KW' | 'A192KW' | 'A256KW' | 'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW'
         *       enc: string, // 'A128CBC-HS256' | 'A128GCM' | 'A192CBC-HS384' | 'A192GCM' | 'A256CBC-HS512' | 'A256GCM'
         *       key: crypto.KeyObject | Buffer, // public key or shared symmetric secret to encrypt the JWT token with
         *       kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWE Header
         *     }
         *   }
         * }
         * ```
         */
        getResourceServerInfo,
      },

      /*
       * features.requestObjects
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject) and [JWT Secured Authorization Request (`JAR`)](https://www.rfc-editor.org/rfc/rfc9101.html) - Request Object
       *
       * description: Enables the use and validations of the `request` and/or `request_uri`
       *   parameters.
       */
      requestObjects: {

        /*
         * features.requestObjects.request
         *
         * description: Enables the use and validations of the `request` parameter.
         */
        request: false,

        /*
         * features.requestObjects.requestUri
         *
         * description: Enables the use and validations of the `request_uri` parameter.
         */
        requestUri: false,

        /*
         * features.requestObjects.requireUriRegistration
         *
         * description: Makes request_uri pre-registration mandatory (true) or optional (false).
         */
        requireUriRegistration: true,

        /*
         * features.requestObjects.requireSignedRequestObject
         *
         * description: Makes the use of signed request objects required for all authorization
         * requests as an OP policy.
         */
        requireSignedRequestObject: false,

        /*
         * features.requestObjects.mode
         *
         * description: defines the provider's strategy when it comes to using regular OAuth 2.0
         * parameters that are present. Parameters inside the Request Object are ALWAYS used,
         * this option controls whether to combine those with the regular ones or not.
         *
         * Supported values are:
         *
         * - 'lax' This is the behaviour expected by `OIDC Core 1.0` - all parameters that
         *   are not present in the Resource Object are used when resolving the authorization
         *   request.
         * - 'strict' (default) All parameters outside of the
         *   Request Object are ignored. For `PAR`, `FAPI`, and `CIBA` this value is enforced.
         *
         */
        mode: 'strict',
      },

      /*
       * features.revocation
       *
       * title: [`RFC7009`](https://www.rfc-editor.org/rfc/rfc7009.html) - OAuth 2.0 Token Revocation
       *
       * description: Enables Token Revocation for:
       *   - opaque access tokens
       *   - refresh tokens
       *
       */
      revocation: { enabled: false },

      /*
       * features.userinfo
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - UserInfo Endpoint
       *
       * description: Enables the userinfo endpoint. Its use requires an opaque Access Token with at least
       * `openid` scope that's without a Resource Server audience.
       */
      userinfo: { enabled: true },

      /*
       * features.jwtUserinfo
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) - JWT UserInfo Endpoint Responses
       *
       * description: Enables the userinfo to optionally return signed and/or encrypted JWTs, also
       * enables the relevant client metadata for setting up signing and/or encryption.
       */
      jwtUserinfo: { enabled: false },

      /*
       * features.webMessageResponseMode
       *
       * title: [draft-sakimura-oauth-wmrm-00](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00) - OAuth 2.0 Web Message Response Mode
       *
       * description: Enables `web_message` response mode.
       *
       * recommendation: Although a general advise to use a `helmet` ([express](https://www.npmjs.com/package/helmet),
       * [koa](https://www.npmjs.com/package/koa-helmet)) it is especially advised for your interaction
       * views routes if Web Message Response Mode is enabled in your deployment.
       *
       * recommendation: Updates to draft specification versions are released as MINOR library versions,
       * if you utilize these specification implementations consider using the tilde `~` operator
       * in your package.json since breaking changes may be introduced as part of these version
       * updates. Alternatively, [acknowledge](#features) the version and be notified of breaking
       * changes as part of your CI.
       *
       * @skip
       */
      webMessageResponseMode: { enabled: false, ack: undefined },
    },

    /*
     * extraTokenClaims
     *
     * description: Function used to add additional claims to an Access Token
     *   when it is being issued. For `opaque` Access Tokens these claims will be stored
     *   in your storage under the `extra` property and returned by introspection as top
     *   level claims. For `jwt` Access Tokens these will be top level claims.
     *   Returned claims will not overwrite pre-existing top level claims.
     *
     * example: To add an arbitrary claim to an Access Token
     * ```js
     * {
     *   async extraTokenClaims(ctx, token) {
     *     return {
     *       'urn:idp:example:foo': 'bar',
     *     };
     *   }
     * }
     * ```
     */
    extraTokenClaims,

    formats: {
      /*
       * formats.bitsOfOpaqueRandomness
       *
       * description: The value should be an integer (or a function returning an integer) and the
       *   resulting opaque token length is equal to `Math.ceil(i / Math.log2(n))` where n is the
       *   number of symbols in the used alphabet, 64 in our case.
       *
       * example: To have e.g. Refresh Tokens values longer than Access Tokens.
       * ```js
       * function bitsOfOpaqueRandomness(ctx, token) {
       *   if (token.kind === 'RefreshToken') {
       *     return 384;
       *   }
       *
       *   return 256;
       * }
       * ```
       */
      bitsOfOpaqueRandomness: 256,

      /*
       * formats.customizers
       *
       * description: Customizer functions used before issuing a structured Access Token.
       *
       * example: To push additional headers and payload claims to a `jwt` format Access Token
       * ```js
       * {
       *   customizers: {
       *     async jwt(ctx, token, jwt) {
       *       jwt.header = { foo: 'bar' };
       *       jwt.payload.foo = 'bar';
       *     }
       *   }
       * }
       * ```
       */
      customizers: {
        jwt: undefined,
      },
    },

    /*
     * httpOptions
     *
     * description: Function called whenever calls to an external HTTP(S) resource are being made.
     * You can change the request timeout through the `signal` option, the request `agent` used,
     * the `user-agent` string used for the `user-agent` HTTP header, as well as the `dnsLookup`
     * resolver function.
     *
     * example: To change the request's timeout
     *
     * To change all request's timeout configure the httpOptions as a function like so:
     *
     * ```js
     *  {
     *    httpOptions(url) {
     *      return { signal: AbortSignal.timeout(5000) };
     *    }
     *  }
     * ```
     */
    httpOptions,

    /*
     * expiresWithSession
     * description: Function used to decide whether the given authorization code, device code, or
     *   authorization-endpoint returned opaque access token be bound to the user session. This will be applied to all
     *   opaque tokens issued from the authorization code, device code, or subsequent refresh token use in the future.
     *   When artifacts are session-bound their originating session will be loaded by its `uid` every time they are encountered.
     *   Session bound artefacts will effectively get revoked if the end-user logs out.
     */
    expiresWithSession,

    /*
     * issueRefreshToken
     *
     * description: Function used to decide whether a refresh token will be issued or not
     *
     * example: To always issue a refresh tokens ...
     * ... if a client has the grant allowed and scope includes offline_access or the client is a
     * public web client doing code flow. Configure `issueRefreshToken` like so
     *
     * ```js
     * async issueRefreshToken(ctx, client, code) {
     *   if (!client.grantTypeAllowed('refresh_token')) {
     *     return false;
     *   }
     *
     *   return code.scopes.has('offline_access') || (client.applicationType === 'web' && client.clientAuthMethod === 'none');
     * }
     * ```
     */
    issueRefreshToken,

    /*
     * jwks
     *
     * description: JSON Web Key Set used by the provider for signing and decryption. The object must
     * be in [JWK Set format](https://www.rfc-editor.org/rfc/rfc7517.html#section-5). All provided keys must
     * be private keys.
     *
     * Supported key types are:
     *
     * - RSA
     * - OKP (Ed25519, Ed448, X25519, X448 sub types)
     * - EC (P-256, secp256k1, P-384, and P-521 curves)
     *
     * recommendation: Be sure to follow best practices for distributing private keying material and secrets
     * for your respective target deployment environment.
     *
     * recommendation: The following action order is recommended when rotating signing keys on a distributed
     * deployment with rolling reloads in place.
     *
     * 1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become
     *    available for verification should they be encountered but not yet used for signing
     * 2. reload all your processes
     * 3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be
     *    used for signing after reload
     * 4. reload all your processes
     *
     * @nodefault
     *
     */
    jwks: JSON.parse(JSON.stringify(DEV_KEYSTORE)),

    /*
     * responseTypes
     *
     * description: Array of response_type values that the OP supports. The default omits all response
     * types that result in access tokens being issued by the authorization endpoint directly as per
     * [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.1.2)
     * You can still enable them if you need to.
     *
     * example: Supported values list
     * These are values defined in [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0.html#Authentication)
     * and [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
     * ```js
     * [
     *   'code',
     *   'id_token', 'id_token token',
     *   'code id_token', 'code token', 'code id_token token',
     *   'none',
     * ]
     * ```
     */
    responseTypes: [
      'code id_token',
      'code',
      'id_token',
      'none',
    ],

    /*
     * pkce
     * title: [`RFC7636` - Proof Key for Code Exchange (`PKCE`)](https://www.rfc-editor.org/rfc/rfc7636.html)
     * description: `PKCE` configuration such as available methods and policy check on required use of
     * `PKCE`
     * @nodefault
     */
    pkce: {
      /*
       * pkce.methods
       *
       * description: Fine-tune the supported code challenge methods. Supported values are
       *   - `S256`
       *   - `plain`
       */
      methods: ['S256'],

      /*
       * pkce.required
       *
       * description: Configures if and when the OP requires clients to use `PKCE`. This helper is called
       * whenever an authorization request lacks the code_challenge parameter.
       * Return
       *   - `false` to allow the request to continue without `PKCE`
       *   - `true` to abort the request
       */
      required: pkceRequired,
    },

    /*
     * routes
     *
     * description: Routing values used by the OP. Only provide routes starting with "/"
     */
    routes: {
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
      userinfo: '/me',
    },

    /*
     * scopes
     *
     * description: Array of additional scope values that the OP signals to support in the discovery
     *   endpoint. Only add scopes the OP has a corresponding resource for.
     *   Resource Server scopes don't belong here, see `features.resourceIndicators` for configuring
     *   those.
     */
    scopes: ['openid', 'offline_access'],

    /*
     * subjectTypes
     *
     * description: Array of the Subject Identifier types that this OP supports. When only `pairwise`
     * is supported it becomes the default `subject_type` client metadata value. Valid types are
     *   - `public`
     *   - `pairwise`
     */
    subjectTypes: ['public'],

    /*
     * pairwiseIdentifier
     *
     * description: Function used by the OP when resolving pairwise ID Token and Userinfo sub claim
     *   values. See [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
     * recommendation: Since this might be called several times in one request with the same arguments
     *   consider using memoization or otherwise caching the result based on account and client
     *   ids.
     */
    pairwiseIdentifier,

    /*
     * clientAuthMethods
     *
     * description: Array of supported Client Authentication methods
     * example: Supported values list
     * ```js
     * [
     *   'none',
     *   'client_secret_basic', 'client_secret_post',
     *   'client_secret_jwt', 'private_key_jwt',
     *   'tls_client_auth', 'self_signed_tls_client_auth', // these methods are only available when features.mTLS is configured
     * ]
     * ```
     */
    clientAuthMethods: [
      'client_secret_basic',
      'client_secret_jwt',
      'client_secret_post',
      'private_key_jwt',
      'none',
    ],

    /*
     * ttl
     *
     * description: description: Expirations for various token and session types.
     * The value can be a number (in seconds) or a synchronous function that dynamically returns
     * value based on the context.
     *
     * recommendation: Do not set token TTLs longer then they absolutely have to be, the shorter
     * the TTL, the better.
     *
     * recommendation: Rather than setting crazy high Refresh Token TTL look into `rotateRefreshToken`
     * configuration option which is set up in way that when refresh tokens are regularly used they
     * will have their TTL refreshed (via rotation). This is inline with the
     * [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13)
     *
     * example: To resolve a ttl on runtime for each new token
     * Configure `ttl` for a given token type with a function like so, this must return a value, not a
     * Promise.
     *
     * ```js
     * {
     *   ttl: {
     *     AccessToken(ctx, token, client) {
     *       // return a Number (in seconds) for the given token (first argument), the associated client is
     *       // passed as a second argument
     *       // Tip: if the values are entirely client based memoize the results
     *       return resolveTTLfor(token, client);
     *     },
     *   },
     * }
     * ```
     */
    ttl: {
      AccessToken: AccessTokenTTL,
      AuthorizationCode: AuthorizationCodeTTL,
      BackchannelAuthenticationRequest: BackchannelAuthenticationRequestTTL,
      ClientCredentials: ClientCredentialsTTL,
      DeviceCode: DeviceCodeTTL,
      Grant: GrantTTL,
      IdToken: IdTokenTTL,
      Interaction: InteractionTTL,
      RefreshToken: RefreshTokenTTL,
      Session: SessionTTL,
    },

    /*
     * extraClientMetadata
     *
     * description: Allows for custom client metadata to be defined, validated, manipulated as well as
     *   for existing property validations to be extended. Existing properties are snakeCased on
     *   a Client instance (e.g. `client.redirectUris`), new properties (defined by this
     *   configuration) will be available with their names verbatim (e.g.
     *   `client['urn:example:client:my-property']`)
     * @nodefault
     */
    extraClientMetadata: {
      /*
       * extraClientMetadata.properties
       *
       * description: Array of property names that clients will be allowed to have defined.
       */
      properties: [],
      /*
       * extraClientMetadata.validator
       *
       * description: validator function that will be executed in order once for every property
       *   defined in `extraClientMetadata.properties`, regardless of its value or presence on the
       *   client metadata passed in. Must be synchronous, async validators or functions returning
       *   Promise will be rejected during runtime. To modify the current client metadata values (for
       *   current key or any other) just modify the passed in `metadata` argument.
       */
      validator: extraClientMetadataValidator,
    },

    /*
     * renderError
     *
     * description: Function used to present errors to the User-Agent
     */
    renderError,

    /*
     * revokeGrantPolicy
     *
     * description: Function called in a number of different context to determine whether
     * an underlying Grant entry should also be revoked or not.
     *
     * contexts:
     * - RP-Initiated Logout
     * - Refresh Token Revocation
     * - Authorization Code re-use
     * - Device Code re-use
     * - Backchannel Authentication Request re-use
     * - Rotated Refresh Token re-use
     */
    revokeGrantPolicy,

    /*
     * sectorIdentifierUriValidate
     *
     * description: Function called to make a decision about whether sectorIdentifierUri of
     * a client being loaded, registered, or updated should be fetched and its contents
     * validated against the client metadata.
     */
    sectorIdentifierUriValidate,

    /*
     * interactions
     *
     * description: Holds the configuration for interaction policy and a URL to send end-users to
     *   when the policy decides to require interaction.
     *
     * @nodefault
     */
    interactions: {
      /*
       * interactions.policy
       *
       * description: structure of Prompts and their checks formed by Prompt and Check class instances.
       *  The default you can get a fresh instance for and the classes are available under
       * `Provider.interactionPolicy`.
       *
       * example: default interaction policy description
       *
       * The default interaction policy consists of two available prompts, login and consent
       *
       * <br/><br/>
       *
       * - `login` does the following checks:
       *   - no_session - checks that there's an established session, an authenticated end-user
       *   - max_age - processes the max_age parameter (when the session's auth_time is too old it requires login)
       *   - id_token_hint - processes the id_token_hint parameter (when the end-user sub differs it requires login)
       *   - claims_id_token_sub_value - processes the claims parameter `sub` (when the `claims` parameter requested sub differs it requires login)
       *   - essential_acrs - processes the claims parameter `acr` (when the current acr is not amongst the `claims` parameter essential `acr.values` it requires login)
       *   - essential_acr - processes the claims parameter `acr` (when the current acr is not equal to the `claims` parameter essential `acr.value` it requires login)
       *
       * <br/><br/>
       *
       * - `consent` does the following checks:
       *   - native_client_prompt - native clients always require re-consent
       *   - op_scopes_missing - requires consent when the requested scope includes scope values previously not requested
       *   - op_claims_missing - requires consent when the requested claims parameter includes claims previously not requested
       *   - rs_scopes_missing - requires consent when the requested resource indicated scope values include scopes previously not requested
       *
       * <br/><br/>
       *
       * These checks are the best practice for various privacy and security reasons.
       *
       * example: disabling default consent checks
       *
       * You may be required to skip (silently accept) some of the consent checks, while it is
       * discouraged there are valid reasons to do that, for instance in some first-party scenarios or
       * going with pre-existing, previously granted, consents. To simply silenty "accept"
       * first-party/resource indicated scopes or pre-agreed upon claims use the `loadExistingGrant`
       * configuration helper function, in there you may just instantiate (and save!) a grant for the
       * current clientId and accountId values.
       *
       * example: modifying the default interaction policy
       * ```js
       * import { interactionPolicy } from 'oidc-provider';
       * const { Prompt, Check, base } = interactionPolicy;
       *
       * const basePolicy = base()
       *
       * // basePolicy.get(name) => returns a Prompt instance by its name
       * // basePolicy.remove(name) => removes a Prompt instance by its name
       * // basePolicy.add(prompt, index) => adds a Prompt instance to a specific index, default is add the prompt as the last one
       *
       * // prompt.checks.get(reason) => returns a Check instance by its reason
       * // prompt.checks.remove(reason) => removes a Check instance by its reason
       * // prompt.checks.add(check, index) => adds a Check instance to a specific index, default is add the check as the last one
       * ```
       */
      policy: defaultPolicy(),

      /*
       * interactions.url
       *
       * description: Function used to determine where to redirect User-Agent for necessary
       *   interaction, can return both absolute and relative urls.
       */
      url: interactionsUrl,
    },

    /*
     * findAccount
     *
     * description: Function used to load an account and retrieve its available claims. The
     *   return value should be a Promise and #claims() can return a Promise too
     */
    findAccount,

    /*
     * rotateRefreshToken
     *
     * description: Configures if and how the OP rotates refresh tokens after they are used. Supported
     *   values are
     *   - `false` refresh tokens are not rotated and their initial expiration date is final
     *   - `true` refresh tokens are rotated when used, current token is marked as
     *     consumed and new one is issued with new TTL, when a consumed refresh token is
     *     encountered an error is returned instead and the whole token chain (grant) is revoked
     *   - `function` returning true/false, true when rotation should occur, false when it shouldn't
     *
     * <br/><br/>
     *
     * The default configuration value puts forth a sensible refresh token rotation policy
     *   - only allows refresh tokens to be rotated (have their TTL prolonged by issuing a new one) for one year
     *   - otherwise always rotate public client tokens that are not sender-constrained
     *   - otherwise only rotate tokens if they're being used close to their expiration (>= 70% TTL passed)
     */
    rotateRefreshToken,

    /*
     * enabledJWA
     *
     * description: Fine-tune the algorithms your provider will support by declaring algorithm
     *   values for each respective JWA use
     * @nodefault
     */
    enabledJWA: {

      /*
       * enabledJWA.clientAuthSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the provider supports for signed JWT Client Authentication
       *
       * example: Supported values list
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES256K', 'ES384', 'ES512',
       *   'EdDSA',
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      clientAuthSigningAlgValues: [
        'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
      ],

      /*
       * enabledJWA.idTokenSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the provider supports to sign ID Tokens with.
       *
       * example: Supported values list
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES256K', 'ES384', 'ES512',
       *   'EdDSA',
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      idTokenSigningAlgValues: [
        'RS256', 'PS256', 'ES256', 'EdDSA',
      ],

      /*
       * enabledJWA.requestObjectSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the provider supports to receive signed Request Objects (`JAR`) with
       *
       * example: Supported values list
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES256K', 'ES384', 'ES512',
       *   'EdDSA',
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      requestObjectSigningAlgValues: [
        'HS256', 'RS256', 'PS256', 'ES256', 'EdDSA',
      ],

      /*
       * enabledJWA.userinfoSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the provider supports to sign UserInfo responses with
       *
       * example: Supported values list
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES256K', 'ES384', 'ES512',
       *   'EdDSA',
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      userinfoSigningAlgValues: [
        'RS256', 'PS256', 'ES256', 'EdDSA',
      ],

      /*
       * enabledJWA.introspectionSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the provider supports to sign JWT Introspection responses with
       *
       * example: Supported values list
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES256K', 'ES384', 'ES512',
       *   'EdDSA',
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      introspectionSigningAlgValues: [
        'RS256', 'PS256', 'ES256', 'EdDSA',
      ],

      /*
       * enabledJWA.authorizationSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the provider supports to sign JWT Authorization Responses (`JARM`) with
       *
       * example: Supported values list
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES256K', 'ES384', 'ES512',
       *   'EdDSA',
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      authorizationSigningAlgValues: [
        'RS256', 'PS256', 'ES256', 'EdDSA',
      ],

      /*
       * enabledJWA.idTokenEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the provider supports for ID Token encryption
       *
       * example: Supported values list
       * ```js
       * [
       *   // asymmetric RSAES based
       *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
       *   // asymmetric ECDH-ES based
       *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
       *   // symmetric AES key wrapping
       *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
       *   // direct encryption
       *   'dir',
       * ]
       * ```
       */
      idTokenEncryptionAlgValues: [
        'A128KW', 'A256KW', 'ECDH-ES', 'RSA-OAEP', 'RSA-OAEP-256', 'dir',
      ],

      /*
       * enabledJWA.requestObjectEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the provider supports to receive encrypted Request Objects (`JAR`) with
       *
       * example: Supported values list
       * ```js
       * [
       *   // asymmetric RSAES based
       *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
       *   // asymmetric ECDH-ES based
       *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
       *   // symmetric AES key wrapping
       *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
       *   // direct encryption
       *   'dir',
       * ]
       * ```
       */
      requestObjectEncryptionAlgValues: [
        'A128KW', 'A256KW', 'ECDH-ES', 'RSA-OAEP', 'RSA-OAEP-256', 'dir',
      ],

      /*
       * enabledJWA.userinfoEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the provider supports for UserInfo Response encryption
       *
       * example: Supported values list
       * ```js
       * [
       *   // asymmetric RSAES based
       *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
       *   // asymmetric ECDH-ES based
       *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
       *   // symmetric AES key wrapping
       *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
       *   // direct encryption
       *   'dir',
       * ]
       * ```
       */
      userinfoEncryptionAlgValues: [
        'A128KW', 'A256KW', 'ECDH-ES', 'RSA-OAEP', 'RSA-OAEP-256', 'dir',
      ],

      /*
       * enabledJWA.introspectionEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the provider supports for JWT Introspection response
       * encryption
       *
       * example: Supported values list
       * ```js
       * [
       *   // asymmetric RSAES based
       *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
       *   // asymmetric ECDH-ES based
       *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
       *   // symmetric AES key wrapping
       *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
       *   // direct encryption
       *   'dir',
       * ]
       * ```
       */
      introspectionEncryptionAlgValues: [
        'A128KW', 'A256KW', 'ECDH-ES', 'RSA-OAEP', 'RSA-OAEP-256', 'dir',
      ],

      /*
       * enabledJWA.authorizationEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the provider supports for JWT Authorization response (`JARM`)
       * encryption
       *
       * example: Supported values list
       * ```js
       * [
       *   // asymmetric RSAES based
       *   'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
       *   // asymmetric ECDH-ES based
       *   'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
       *   // symmetric AES key wrapping
       *   'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
       *   // direct encryption
       *   'dir',
       * ]
       * ```
       */
      authorizationEncryptionAlgValues: [
        'A128KW', 'A256KW', 'ECDH-ES', 'RSA-OAEP', 'RSA-OAEP-256', 'dir',
      ],

      /*
       * enabledJWA.idTokenEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the provider supports to encrypt ID Tokens with
       *
       * example: Supported values list
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      idTokenEncryptionEncValues: [
        'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
      ],

      /*
       * enabledJWA.requestObjectEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the provider supports to decrypt Request Objects (`JAR`) with
       *
       * example: Supported values list
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      requestObjectEncryptionEncValues: [
        'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
      ],

      /*
       * enabledJWA.userinfoEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the provider supports to encrypt UserInfo responses with
       *
       * example: Supported values list
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      userinfoEncryptionEncValues: [
        'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
      ],

      /*
       * enabledJWA.introspectionEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the provider supports to encrypt JWT Introspection responses with
       *
       * example: Supported values list
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      introspectionEncryptionEncValues: [
        'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
      ],

      /*
       * enabledJWA.authorizationEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the provider supports to encrypt JWT Authorization Responses (`JARM`) with
       *
       * example: Supported values list
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      authorizationEncryptionEncValues: [
        'A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM',
      ],

      /*
       * enabledJWA.dPoPSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the provider supports to verify signed DPoP proof JWTs with
       *
       * example: Supported values list
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES256K', 'ES384', 'ES512',
       *   'EdDSA',
       * ]
       * ```
       */
      dPoPSigningAlgValues: [
        'ES256', 'EdDSA',
      ],
    },
  };

  return defaults;
}

export default makeDefaults;
export const defaults = makeDefaults();
