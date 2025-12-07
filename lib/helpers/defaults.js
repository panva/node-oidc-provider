/* eslint-disable no-shadow */
/* eslint-disable no-unused-vars */

import * as crypto from 'node:crypto';

import * as attention from './attention.js';
import nanoid from './nanoid.js';
import { base as defaultPolicy } from './interaction_policy/index.js';
import htmlSafe from './html_safe.js';
import * as errors from './errors.js';

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
  shouldChange('clientBasedCORS', 'control allowed CORS Origins based on the client making a CORS request');
  if (ctx.oidc.route === 'userinfo' || client.clientAuthMethod === 'none') {
    return client.redirectUris.some((uri) => URL.parse(uri)?.origin === origin);
  }
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

function fetch(url, options) {
  /* eslint-disable no-param-reassign */
  options.signal = AbortSignal.timeout(2500);
  options.headers = new Headers(options.headers);
  options.headers.set('user-agent', ''); // removes the user-agent header in Node's global fetch()
  // eslint-disable-next-line no-undef
  return globalThis.fetch(url, options);
  /* eslint-enable no-param-reassign */
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
    <html>
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

async function getAttestationSignaturePublicKey(ctx, iss, header, client) {
  // @param ctx - koa request context
  // @param iss - Issuer Identifier from the Client Attestation JWT
  // @param header - Protected Header of the Client Attestation JWT
  // @param client - client making the request
  mustChange('features.attestClientAuth.getAttestationSignaturePublicKey', 'be able to verify the Client Attestation JWT signature');
  throw new Error('features.attestClientAuth.getAttestationSignaturePublicKey not implemented');
}

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

async function userCodeConfirmSource(ctx, form, client, deviceInfo, userCode) {
  // @param ctx - koa request context
  // @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and
  //   submitted by the End-User.
  // @param deviceInfo - device information from the device_authorization_endpoint call
  // @param userCode - formatted user code by the configured mask
  shouldChange('features.deviceFlow.userCodeConfirmSource', 'customize the look of the user code confirmation page');
  ctx.body = `<!DOCTYPE html>
    <html>
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
          <strong>${ctx.oidc.client.clientName || ctx.oidc.client.clientId}</strong>
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
  ctx.body = `<!DOCTYPE html>
    <html>
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
        <p>Your sign-in ${ctx.oidc.client.clientName ? `with ${ctx.oidc.client.clientName}` : ''} was successful, you can now close this page.</p>
      </div>
    </body>
    </html>`;
}

async function introspectionAllowedPolicy(ctx, client, token) {
  // @param ctx - koa request context
  // @param client - authenticated client making the request
  // @param token - token being introspected
  shouldChange('features.introspection.allowedPolicy', 'to check whether the caller is authorized to receive the introspection response');

  if (
    client.clientAuthMethod === 'none'
    && token.clientId !== ctx.oidc.client.clientId
  ) {
    return false;
  }

  return true;
}

async function revocationAllowedPolicy(ctx, client, token) {
  // @param ctx - koa request context
  // @param client - authenticated client making the request
  // @param token - token being revoked
  shouldChange('features.revocation.allowedPolicy', 'to check whether the caller is authorized to revoke the token');

  if (token.clientId !== client.clientId) {
    if (client.clientAuthMethod === 'none') {
      // do not revoke but respond as success to disallow guessing valid tokens
      return false;
    }

    throw new errors.InvalidRequest('client is not authorized to revoke the presented token');
  }

  return true;
}

function idFactory(ctx) {
  return nanoid();
}

async function secretFactory(ctx) {
  return crypto.randomBytes(64).toString('base64url');
}

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

async function expiresWithSession(ctx, code) {
  return !code.scopes.has('offline_access');
}

async function issueRefreshToken(ctx, client, code) {
  return (
    client.grantTypeAllowed('refresh_token')
    && code.scopes.has('offline_access')
  );
}

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

async function pairwiseIdentifier(ctx, accountId, client) {
  mustChange('pairwiseIdentifier', 'provide an implementation for pairwise identifiers');
  throw new Error('pairwiseIdentifier not implemented');
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
  if (ctx?.oidc?.params.requested_expiry) {
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
    ctx?.oidc?.entities.RotatedRefreshToken
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
}

async function postLogoutSuccessSource(ctx) {
  // @param ctx - koa request context
  shouldChange('features.rpInitiatedLogout.postLogoutSuccessSource', 'customize the look of the default post logout success page');
  const display = ctx.oidc.client?.clientName || ctx.oidc.client?.clientId;
  ctx.body = `<!DOCTYPE html>
    <html>
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
    <html>
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
    <html>
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
  if (
    client.clientAuthMethod === 'none'
    && !refreshToken.isSenderConstrained()
  ) {
    return true;
  }

  // rotate if the token is nearing expiration (it's beyond 70% of its lifetime)
  return refreshToken.ttlPercentagePassed() >= 70;
}

async function loadExistingGrant(ctx) {
  const grantId = ctx.oidc.result?.consent?.grantId
    || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);

  if (grantId) {
    return ctx.oidc.provider.Grant.find(grantId);
  }
  return undefined;
}

function revokeGrantPolicy(ctx) {
  if (ctx.oidc.route === 'revocation' && ctx.oidc.entities.AccessToken) {
    return false;
  }
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
  if (bindingMessage?.match(/^[a-zA-Z0-9-._+/!?#]{1,20}$/) === null) {
    throw new errors.InvalidBindingMessage(
      'the binding_message value, when provided, needs to be 1 - 20 characters in length and use only a basic set of characters (matching the regex: ^[a-zA-Z0-9-._+/!?#]{1,20}$ )',
    );
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

async function assertClaimsParameter(ctx, claims, client) {
  // @param ctx - koa request context
  // @param claims - parsed claims parameter
  // @param client - the Client instance
}

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

function makeDefaults() {
  const defaults = {
    /*
     * acrValues
     *
     * description: An array of strings representing the Authentication Context Class References
     *   that this authorization server supports.
     */
    acrValues: [],

    /*
     * adapter
     *
     * description: Specifies the storage adapter implementation for persisting authorization server
     *   state. The default implementation provides a basic in-memory adapter suitable for development
     *   and testing purposes only. When this process is restarted, all stored information will be lost.
     *   Production deployments MUST provide a custom adapter implementation that persists data to
     *   external storage (e.g., database, Redis, etc.).
     *
     * The adapter constructor will be instantiated for each model type when first accessed.
     *
     * see: [The expected interface](/example/my_adapter.js)
     * see: [Example MongoDB adapter implementation](https://github.com/panva/node-oidc-provider/discussions/1308)
     * see: [Example Redis adapter implementation](https://github.com/panva/node-oidc-provider/discussions/1309)
     * see: [Example Redis w/ JSON Adapter](https://github.com/panva/node-oidc-provider/discussions/1310)
     * see: [Default in-memory adapter implementation](/lib/adapters/memory_adapter.js)
     * see: [Community Contributed Adapter Archive](https://github.com/panva/node-oidc-provider/discussions/1311)
     *
     * @nodefault
     */
    adapter: undefined,

    /*
     * claims
     *
     * description: Describes the claims that this authorization server may be able to supply values for.
     *
     * It is used to achieve two different things related to claims:
     * - which additional claims are available to RPs (configure as `{ claimName: null }`)
     * - which claims fall under what scope (configure `{ scopeName: ['claim', 'another-claim'] }`)
     *
     * see: [Configuring OpenID Connect 1.0 Standard Claims](https://github.com/panva/node-oidc-provider/discussions/1299)
     */
    claims: {
      acr: null,
      sid: null,
      auth_time: null,
      iss: null,
      openid: ['sub'],
    },

    /*
     * clientBasedCORS
     *
     * description: Specifies a function that determines whether Cross-Origin Resource Sharing (CORS)
     *   requests shall be permitted based on the requesting client. This function
     *   is invoked for each CORS preflight and actual request to evaluate the client's authorization
     *   to access the authorization server from the specified origin.
     *
     * see: [Configuring Client Metadata-based CORS Origin allow list](https://github.com/panva/node-oidc-provider/discussions/1298)
     */
    clientBasedCORS,

    /*
     * clients
     *
     * description: An array of client metadata objects representing statically configured OAuth 2.0
     *   and OpenID Connect clients. These clients are persistent, do not expire, and remain available
     *   throughout the authorization server's lifetime. For dynamic client discovery, the authorization
     *   server will invoke the adapter's `find` method when encountering unregistered client identifiers.
     *
     * To restrict the authorization server to only statically configured clients and disable dynamic
     *   registration, configure the adapter to return falsy values for client lookup operations
     *   (e.g., `return Promise.resolve()`).
     *
     * Each client's metadata shall be validated according to the specifications in which the respective
     *   properties are defined.
     *
     * example: Available Metadata.
     *
     * application_type, client_id, client_name, client_secret, client_uri, contacts,
     * default_acr_values, default_max_age, grant_types, id_token_signed_response_alg,
     * initiate_login_uri, jwks, jwks_uri, logo_uri, policy_uri, post_logout_redirect_uris,
     * redirect_uris, require_auth_time, response_types, response_modes, scope, sector_identifier_uri,
     * subject_type, token_endpoint_auth_method, tos_uri, userinfo_signed_response_alg
     *
     * <br/><br/>The following metadata is available but may not be recognized depending on this
     * authorization server's configuration.<br/><br/>
     *
     * authorization_encrypted_response_alg, authorization_encrypted_response_enc,
     * authorization_signed_response_alg, backchannel_logout_session_required, backchannel_logout_uri,
     * id_token_encrypted_response_alg,
     * id_token_encrypted_response_enc, introspection_encrypted_response_alg,
     * introspection_encrypted_response_enc, introspection_signed_response_alg,
     * request_object_encryption_alg, request_object_encryption_enc, request_object_signing_alg,
     * tls_client_auth_san_dns, tls_client_auth_san_email, tls_client_auth_san_ip,
     * tls_client_auth_san_uri, tls_client_auth_subject_dn,
     * tls_client_certificate_bound_access_tokens,
     * use_mtls_endpoint_aliases, token_endpoint_auth_signing_alg,
     * userinfo_encrypted_response_alg, userinfo_encrypted_response_enc
     *
     */
    clients: [],

    /*
     * clientDefaults
     *
     * description: Specifies default client metadata values that shall be applied when properties
     *   are not explicitly provided during Dynamic Client Registration or for statically configured
     *   clients. This configuration allows override of the authorization server's built-in default
     *   values for any supported client metadata property.
     *
     * example: Changing the default client token_endpoint_auth_method.
     *
     * To change the default client token_endpoint_auth_method, configure `clientDefaults` to be an
     * object like so:
     *
     * ```js
     * {
     *   token_endpoint_auth_method: 'client_secret_post'
     * }
     * ```
     * example: Changing the default client response type to `code id_token`.
     *
     * To change the default client response_types, configure `clientDefaults` to be an
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
     * description: Specifies the maximum acceptable clock skew tolerance (in seconds) for validating
     *   time-sensitive operations, including JWT validation for Request Objects, DPoP Proofs, and
     *   other timestamp-based security mechanisms.
     *
     * recommendation: This value should be kept as small as possible while accommodating expected
     *   clock drift between the authorization server and client systems.
     */
    clockTolerance: 15,

    /*
     * conformIdTokenClaims
     *
     * title: ID Token only contains End-User claims when the requested `response_type` is `id_token`
     *
     * description: [`OIDC Core 1.0` - Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ScopeClaims)
     * defines that claims requested using the `scope` parameter are only returned from the UserInfo
     * Endpoint unless the `response_type` is `id_token`.
     *
     * Despite this configuration, the ID Token always includes claims requested using the `scope`
     * parameter when the userinfo endpoint is disabled, or when issuing an Access Token not applicable
     * for access to the userinfo endpoint.
     *
     */
    conformIdTokenClaims: true,

    /*
     * loadExistingGrant
     *
     * description: Helper function invoked to load existing authorization grants that may be used
     *   to resolve an Authorization Request without requiring additional end-user interaction.
     *   The default implementation attempts to load grants based on the interaction result's
     *   `consent.grantId` property, falling back to the existing grantId for the requesting client
     *   in the current session.
     */
    loadExistingGrant,

    /*
     * allowOmittingSingleRegisteredRedirectUri
     *
     * title: Redirect URI Parameter Omission for Single Registered URI
     *
     * description: Specifies whether clients may omit the `redirect_uri` parameter in authorization
     *   requests when only a single redirect URI is registered in their client metadata. When enabled,
     *   the authorization server shall automatically use the sole registered redirect URI for clients
     *   that have exactly one URI configured.
     *
     * When disabled, all authorization requests MUST explicitly include the `redirect_uri` parameter
     *   regardless of the number of registered redirect URIs.
     */
    allowOmittingSingleRegisteredRedirectUri: true,

    /*
     * acceptQueryParamAccessTokens
     *
     * description: Controls whether access tokens may be transmitted via URI query parameters.
     *   Several OAuth 2.0 and OpenID Connect profiles require that access tokens be transmitted
     *   exclusively via the Authorization header. When set to false, the authorization server
     *   shall reject requests attempting to transmit access tokens via query parameters.
     *
     */
    acceptQueryParamAccessTokens: false,

    /*
     * cookies
     *
     * description: Configuration for HTTP cookies used to maintain User-Agent state throughout
     *   the authorization flow. These settings conform to the
     *   [cookies module interface specification](https://github.com/pillarjs/cookies/tree/0.9.1?tab=readme-ov-file#cookiessetname--values--options).
     *   The `maxAge` and `expires` properties are ignored; cookie lifetimes are instead controlled
     *   via the `ttl.Session` and `ttl.Interaction` configuration parameters.
     * @nodefault
     */
    cookies: {
      /*
       * cookies.names
       *
       * description: Specifies the HTTP cookie names used for state management during the
       *   authorization flow.
       */
      names: {
        session: '_session', // used for main session reference
        interaction: '_interaction', // used by the interactions for interaction session reference
        resume: '_interaction_resume', // used when interactions resume authorization for interaction session reference
      },

      /*
       * cookies.long
       *
       * description: Options for long-term cookies.
       */
      long: {
        httpOnly: true, // cookies are not readable by client-side JavaScript
        sameSite: 'lax',
      },

      /*
       * cookies.short
       *
       * description: Options for short-term cookies.
       */
      short: {
        httpOnly: true, // cookies are not readable by client-side JavaScript
        sameSite: 'lax',
      },

      /*
       * cookies.keys
       *
       * description: [Keygrip](https://www.npmjs.com/package/keygrip) signing keys used for cookie
       *   signing to prevent tampering. You may also pass your own KeyGrip instance.
       *
       * recommendation: Rotate regularly (by prepending new keys) with a reasonable interval and keep
       *   a reasonable history of keys to allow for returning user session cookies to still be valid
       *   and re-signed.
       *
       * @skip
       */
      keys: [],
    },

    /*
     * discovery
     *
     * description: Pass additional properties to this object to extend the discovery document.
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
     * description: Specifies additional parameters that shall be recognized by the authorization,
     *   device authorization, backchannel authentication, and pushed authorization request endpoints.
     *   These extended parameters become available in `ctx.oidc.params` and are passed to interaction
     *   session details for processing.
     *
     * This configuration accepts either an iterable object (array or Set of strings) for simple
     *   parameter registration, or a plain object with string properties representing parameter names
     *   and values being validation functions (synchronous or asynchronous) for the corresponding
     *   parameter values.
     *
     * Parameter validators are executed regardless of the parameter's presence or value, enabling
     *   validation of parameter presence as well as assignment of default values. When the value
     *   is `null` or `undefined`, the parameter is registered without validation constraints.
     *
     * Note: These validators execute during the final phase of the request validation process.
     *   Modifications to other parameters (such as assigning default values) will not trigger
     *   re-validation of the entire request.
     *
     * example: Registering an extra `origin` parameter with its validator.
     *
     * ```js
     * import { errors } from 'oidc-provider';
     *
     * const extraParams = {
     *   async origin(ctx, value, client) {
     *     // @param ctx - koa request context
     *     // @param value - the `origin` parameter value (string or undefined)
     *     // @param client - client making the request
     *
     *     if (hasDefaultOrigin(client)) {
     *       // assign default
     *       ctx.oidc.params.origin ||= value ||= getDefaultOrigin(client);
     *     }
     *
     *     if (!value && requiresOrigin(ctx, client)) {
     *       // reject when missing but required
     *       throw new errors.InvalidRequest('"origin" is required for this request')
     *     }
     *
     *     if (!allowedOrigin(value, client)) {
     *       // reject when not allowed
     *       throw new errors.InvalidRequest('requested "origin" is not allowed for this client')
     *     }
     *   }
     * }
     * ```
     */
    extraParams: [],

    /*
     * features
     *
     * description: Specifies the authorization server feature capabilities that shall be enabled
     *   or disabled. This configuration controls the availability of optional OAuth 2.0 and
     *   OpenID Connect extensions, experimental specifications, and proprietary enhancements.
     *
     * Certain features may be designated as experimental implementations. When experimental
     *   features are enabled, the authorization server will emit warnings to indicate that
     *   breaking changes may occur in future releases. These changes will be published as
     *   minor version updates of the oidc-provider module.
     *
     * To suppress experimental feature warnings and ensure configuration validation against
     *   breaking changes, implementations shall acknowledge the specific experimental feature
     *   version using the acknowledgment mechanism demonstrated in the example below. When
     *   an unacknowledged breaking change is detected, the authorization server configuration
     *   will throw an error during instantiation.
     *
     * example: Acknowledging an experimental feature.
     *
     * ```js
     * import * as oidc from 'oidc-provider'
     *
     * new oidc.Provider('http://localhost:3000', {
     *   features: {
     *     webMessageResponseMode: {
     *       enabled: true,
     *     },
     *   },
     * });
     *
     * // The above code produces this NOTICE
     * // NOTICE: The following experimental features are enabled and their implemented version not acknowledged
     * // NOTICE:   - OAuth 2.0 Web Message Response Mode - draft 01 (Acknowledging this feature's implemented version can be done with the value 'individual-draft-01')
     * // NOTICE: Breaking changes between experimental feature updates may occur and these will be published as MINOR semver oidc-provider updates.
     * // NOTICE: You may disable this notice and be warned when breaking updates occur by acknowledging the current experiment's version. See the documentation for more details.
     *
     * new oidc.Provider('http://localhost:3000', {
     *   features: {
     *     webMessageResponseMode: {
     *       enabled: true,
     *       ack: 'individual-draft-01',
     *     },
     *   },
     * });
     * // No more NOTICE, at this point if the experimental was updated and contained no breaking
     * // changes, you're good to go, still no NOTICE, your code is safe to run.
     *
     * // Now lets assume you upgrade oidc-provider version and it includes a breaking change in
     * // this experimental feature
     * new oidc.Provider('http://localhost:3000', {
     *   features: {
     *     webMessageResponseMode: {
     *       enabled: true,
     *       ack: 'individual-draft-01',
     *     },
     *   },
     * });
     * // Thrown:
     * // Error: An unacknowledged version of an experimental feature is included in this oidc-provider version.
     * ```
     * @nodefault
     */
    features: {
      /*
       * features.devInteractions
       *
       * description: Enables development-only interaction views that provide pre-built user
       *   interface components for rapid prototyping and testing of authorization flows. These
       *   views accept any username (used as the subject claim value) and any password for
       *   authentication, bypassing production-grade security controls.
       *
       * Production deployments MUST disable this feature and implement proper end-user
       *   authentication and authorization mechanisms. These development views MUST NOT
       *   be used in production environments as they provide no security guarantees and
       *   accept arbitrary credentials.
       */
      devInteractions: { enabled: true },

      /*
       * features.dPoP
       *
       * title: [`RFC9449`](https://www.rfc-editor.org/rfc/rfc9449.html) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (`DPoP`)
       *
       * description: Enables sender-constraining of OAuth 2.0 tokens through application-level
       *   proof-of-possession mechanisms.
       */
      dPoP: {
        enabled: true,

        /**
         * features.dPoP.nonceSecret
         *
         * description: Specifies the cryptographic secret value used for generating server-provided
         *   DPoP nonces. When provided, this value MUST be a 32-byte length
         *   Buffer instance to ensure sufficient entropy for secure nonce generation.
         */
        nonceSecret: undefined,
        /**
         * features.dPoP.requireNonce
         *
         * description: Specifies a function that determines whether a DPoP nonce shall be required
         *   for proof-of-possession validation in the current request context. This function is
         *   invoked during DPoP proof validation to enforce nonce requirements based on
         *   authorization server policy.
         */
        requireNonce,
        /**
         * features.dPoP.allowReplay
         *
         * description: Specifies whether DPoP Proof replay shall be permitted by the
         *   authorization server. When set to false, the server enforces strict replay protection
         *   by rejecting previously used DPoP proofs, enhancing security against replay attacks.
         */
        allowReplay: false,
      },

      /*
       * features.backchannelLogout
       *
       * title: [`OIDC Back-Channel Logout 1.0`](https://openid.net/specs/openid-connect-backchannel-1_0-final.html)
       *
       * description: Specifies whether Back-Channel Logout capabilities shall be enabled. When
       *   enabled, the authorization server shall support propagating end-user logouts initiated
       *   by relying parties to clients that were involved throughout the lifetime of the
       *   terminated session.
       */
      backchannelLogout: { enabled: false },

      /*
       * features.ciba
       *
       * title: [OIDC Client Initiated Backchannel Authentication Flow (`CIBA`)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)
       *
       * description: Enables Core `CIBA` Flow, when combined with `features.fapi` and
       *   `features.requestObjects.enabled` enables
       *   [Financial-grade API: Client Initiated Backchannel Authentication Profile - Implementers Draft 01](https://openid.net/specs/openid-financial-api-ciba-ID1.html)
       *   as well.
       *
       */
      ciba: {
        enabled: false,

        /*
         * features.ciba.deliveryModes
         *
         * description: Specifies the token delivery modes supported by this authorization server.
         *   The following delivery modes are defined:
         *   - `poll` - Client polls the token endpoint for completion
         *   - `ping` - Authorization server notifies client of completion via HTTP callback
         *
         */
        deliveryModes: ['poll'],

        /*
         * features.ciba.triggerAuthenticationDevice
         *
         * description: Specifies a helper function that shall be invoked to initiate authentication
         *   and authorization processes on the end-user's Authentication Device as defined in the
         *   CIBA specification. This function is executed after accepting the backchannel
         *   authentication request but before transmitting the response to the requesting client.
         *
         * Upon successful end-user authentication, implementations shall use `provider.backchannelResult()`
         *   to complete the Consumption Device login process.
         *
         * example: `provider.backchannelResult()` method.
         *
         * `backchannelResult` is a method on the Provider prototype, it returns a `Promise` with no fulfillment value.
         *
         * ```js
         * import * as oidc from 'oidc-provider';
         * const provider = new oidc.Provider(...);
         * await provider.backchannelResult(...);
         * ```
         *
         * `backchannelResult(request, result[, options]);`
         * - `request` BackchannelAuthenticationRequest - BackchannelAuthenticationRequest instance.
         * - `result` Grant | OIDCProviderError - instance of a persisted Grant model or an OIDCProviderError (all exported by errors).
         * - `options.acr?`: string - Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied.
         * - `options.amr?`: string[] - Identifiers for authentication methods used in the authentication.
         * - `options.authTime?`: number - Time when the end-user authentication occurred.
         *
         */
        triggerAuthenticationDevice,

        /*
         * features.ciba.validateBindingMessage
         *
         * description: Specifies a helper function that shall be invoked to validate the
         *   `binding_message` parameter according to authorization server policy. This function
         *   MUST reject invalid binding messages by throwing appropriate error instances.
         *
         * recommendation: Use `throw new errors.InvalidBindingMessage('validation error message')`
         *   when the binding_message violates authorization server policy.
         * recommendation: Use `return undefined` when a binding_message is not required by policy
         *   and was not provided in the request.
         *
         */
        validateBindingMessage,

        /*
         * features.ciba.validateRequestContext
         *
         * description: Specifies a helper function that shall be invoked to validate the
         *   `request_context` parameter according to authorization server policy. This function
         *   MUST enforce policy requirements for request context validation and reject
         *   non-compliant requests.
         *
         * recommendation: Use `throw new errors.InvalidRequest('validation error message')`
         *   when the request_context is required by policy but missing or invalid.
         * recommendation: Use `return undefined` when a request_context is not required by policy
         *   and was not provided in the request.
         *
         */
        validateRequestContext,

        /*
         * features.ciba.processLoginHintToken
         *
         * description: Specifies a helper function that shall be invoked to process the
         *   `login_hint_token` parameter and extract the corresponding accountId value for
         *   request processing. This function MUST validate token expiration and format
         *   according to authorization server policy.
         *
         * recommendation: Use `throw new errors.ExpiredLoginHintToken('validation error message')`
         *   when the login_hint_token has expired.
         * recommendation: Use `throw new errors.InvalidRequest('validation error message')`
         *   when the login_hint_token format or content is invalid.
         * recommendation: Use `return undefined` when the accountId cannot be determined
         *   from the provided login_hint_token.
         *
         */
        processLoginHintToken,

        /*
         * features.ciba.processLoginHint
         *
         * description: Specifies a helper function that shall be invoked to process the
         *   `login_hint` parameter and extract the corresponding accountId value for
         *   request processing. This function MUST validate the hint format and content
         *   according to authorization server policy.
         *
         * recommendation: Use `throw new errors.InvalidRequest('validation error message')`
         *   when the login_hint format or content is invalid.
         * recommendation: Use `return undefined` when the accountId cannot be determined
         *   from the provided login_hint.
         *
         */
        processLoginHint,

        /*
         * features.ciba.verifyUserCode
         *
         * description: Specifies a helper function that shall be invoked to verify the presence
         *   and validity of the `user_code` parameter when required by authorization server policy.
         *
         * recommendation: Use `throw new errors.MissingUserCode('validation error message')`
         *   when user_code is required by policy but was not provided.
         * recommendation: Use `throw new errors.InvalidUserCode('validation error message')`
         *   when the provided user_code value is invalid or does not meet policy requirements.
         * recommendation: Use `return undefined` when no user_code was provided and it is not
         *   required by authorization server policy.
         *
         */
        verifyUserCode,
      },

      /*
       * features.mTLS
       *
       * title: [`RFC8705`](https://www.rfc-editor.org/rfc/rfc8705.html) - OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens (`MTLS`)
       *
       * description: Specifies whether Mutual TLS capabilities shall be enabled.
       * The authorization server supports three distinct features that require separate configuration
       * settings within this feature's configuration object. Implementations MUST provide
       * deployment-specific helper functions for certificate validation and processing operations.
       *
       */
      mTLS: {
        enabled: false,

        /*
         * features.mTLS.certificateBoundAccessTokens
         *
         * description: Specifies whether Certificate-Bound Access Tokens shall be enabled as
         *   defined in RFC 8705 sections 3 and 4. When enabled, the authorization server shall
         *   expose the client's `tls_client_certificate_bound_access_tokens` metadata property
         *   for mutual TLS certificate binding functionality.
         */
        certificateBoundAccessTokens: false,

        /*
         * features.mTLS.selfSignedTlsClientAuth
         *
         * description: Specifies whether Self-Signed Certificate Mutual TLS client authentication
         *   shall be enabled as defined in RFC 8705 section 2.2. When enabled, the authorization
         *   server shall support the `self_signed_tls_client_auth` authentication method within
         *   the server's `clientAuthMethods` configuration.
         */
        selfSignedTlsClientAuth: false,

        /*
         * features.mTLS.tlsClientAuth
         *
         * description: Specifies whether PKI Mutual TLS client authentication shall be enabled
         *   as defined in RFC 8705 section 2.1. When enabled, the authorization server shall
         *   support the `tls_client_auth` authentication method within the server's
         *   `clientAuthMethods` configuration.
         */
        tlsClientAuth: false,

        /*
         * features.mTLS.getCertificate
         *
         * description: Specifies a helper function that shall be invoked to retrieve the client
         *   certificate used in the current request. This function MUST return either a
         *   `crypto.X509Certificate` instance or a PEM-formatted string representation of
         *   the client certificate for mutual TLS processing.
         */
        getCertificate,

        /*
         * features.mTLS.certificateAuthorized
         *
         * description: Specifies a helper function that shall be invoked to determine whether
         *   the client certificate used in the request is verified and originates from a trusted
         *   Certificate Authority for the requesting client. This function MUST return a boolean
         *   value indicating certificate authorization status. This validation is exclusively
         *   used for the `tls_client_auth` client authentication method.
         */
        certificateAuthorized,

        /*
         * features.mTLS.certificateSubjectMatches
         *
         * description: Specifies a helper function that shall be invoked to determine whether
         *   the client certificate subject used in the request matches the registered client
         *   property according to authorization server policy. This function MUST return a
         *   boolean value indicating subject matching status. This validation is exclusively
         *   used for the `tls_client_auth` client authentication method.
         */
        certificateSubjectMatches,
      },

      /*
       * features.attestClientAuth
       *
       * title: [`draft-ietf-oauth-attestation-based-client-auth-06`](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-06.html) - OAuth 2.0 Attestation-Based Client Authentication
       *
       * description: Specifies whether Attestation-Based Client Authentication capabilities
       *   shall be enabled. When enabled, the
       *   authorization server shall support the `attest_jwt_client_auth` authentication
       *   method within the server's `clientAuthMethods` configuration. This mechanism
       *   enables Client Instances to authenticate using a Client Attestation JWT issued
       *   by a trusted Client Attester and a corresponding Client Attestation Proof-of-Possession
       *   JWT generated by the Client Instance.
       *
       */
      attestClientAuth: {
        ack: undefined,
        enabled: false,

        /**
         * features.attestClientAuth.challengeSecret
         *
         * description: Specifies the cryptographic secret value used for generating server-provided
         *   challenges. This value MUST be a 32-byte length
         *   Buffer instance to ensure sufficient entropy for secure challenge generation.
         */
        challengeSecret: undefined,

        /**
         * features.attestClientAuth.getAttestationSignaturePublicKey
         *
         * description: Specifies a helper function that shall be invoked to verify the issuer
         *   identifier of a Client Attestation JWT and retrieve the public key used for signature
         *   verification. At the point of this function's invocation, only the
         *   JWT format has been validated; no cryptographic or claims verification has occurred.
         *
         * The function MUST return a public key in one of the supported formats: CryptoKey,
         *   KeyObject, or JSON Web Key (JWK) representation. The authorization server shall
         *   use this key to verify the Client Attestation JWT signature.
         *
         * example: Fetching attester public keys from the attester's hosted JWKS
         *
         * ```js
         * import * as jose from 'jose';
         *
         * const attesters = new Map(Object.entries({
         *   'https://attester.example.com': jose.createRemoteJWKSet(new URL('https://attester.example.com/jwks')),
         * }));
         *
         * function getAttestationSignaturePublicKey(ctx, iss, header, client) {
         *   if (attesters.has(iss)) return attesters.get(iss)(header);
         *   throw new Error('unsupported oauth-client-attestation issuer');
         * }
         * ```
         */
        getAttestationSignaturePublicKey,

        /**
         * features.attestClientAuth.assertAttestationJwtAndPop
         *
         * description: Specifies a helper function that shall be invoked to perform additional
         *   validation of the Client Attestation JWT and Client Attestation Proof-of-Possession
         *   JWT beyond the specification requirements. This enables enforcement of extension
         *   profiles, deployment-specific policies, or additional security constraints.
         *
         * At the point of invocation, both JWTs have undergone signature verification and
         *   standard validity claim validation. The function may throw errors to reject
         *   non-compliant attestations
         *   or return successfully to indicate acceptance of the client authentication attempt.
         */
        assertAttestationJwtAndPop,
      },

      /*
       * features.claimsParameter
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ClaimsParameter) - Requesting Claims using the "claims" Request Parameter
       *
       * description: Specifies whether the `claims` request parameter shall be enabled for
       *   authorization requests.
       *   When enabled, the authorization server shall accept and process
       *   the `claims` parameter to enable fine-grained control over which claims are
       *   returned in ID Tokens and from the UserInfo Endpoint.
       *
       */
      claimsParameter: {
        enabled: false,

        /**
         * features.claimsParameter.assertClaimsParameter
         *
         * description: Specifies a helper function that shall be invoked to perform additional
         *   validation of the `claims` parameter. This function enables enforcement of
         *   deployment-specific policies, security constraints, or extended claim validation
         *   logic according to authorization server requirements.
         *
         * The function may throw errors to reject non-compliant claims requests or return
         *   successfully to indicate acceptance of the claims parameter content.
         */
        assertClaimsParameter,
      },

      /*
       * features.clientCredentials
       *
       * title: [`RFC6749`](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3.4) - Client Credentials
       *
       * description: Specifies whether the Client Credentials grant type shall be enabled.
       *   When enabled, the authorization server
       *   shall accept `grant_type=client_credentials` requests at the token endpoint,
       *   allowing clients to obtain access tokens.
       */
      clientCredentials: { enabled: false },

      /*
       * features.deviceFlow
       *
       * title: [`RFC8628`](https://www.rfc-editor.org/rfc/rfc8628.html) - OAuth 2.0 Device Authorization Grant (`Device Flow`)
       *
       * description: Specifies whether the OAuth 2.0 Device Authorization Grant shall be enabled.
       *   When enabled, the authorization server shall support the device
       *   authorization flow, enabling OAuth clients on input-constrained devices to obtain
       *   user authorization by directing the user to perform the authorization flow on a
       *   secondary device with richer input and display capabilities.
       */
      deviceFlow: {
        enabled: false,

        /*
         * features.deviceFlow.charset
         *
         * description: Specifies the character set used for generating user codes in the device
         *   authorization flow. This configuration determines the alphabet from which user codes
         *   are constructed. Supported values include:
         *   - `base-20` - Uses characters BCDFGHJKLMNPQRSTVWXZ (excludes easily confused characters)
         *   - `digits` - Uses characters 0123456789 (numeric only)
         */
        charset: 'base-20',

        /*
         * features.deviceFlow.mask
         *
         * description: Specifies the template pattern used for generating user codes in the device
         *   authorization flow. The authorization server shall replace `*` characters with random
         *   characters from the configured charset, while `-` (dash) and ` ` (space) characters
         *   may be included for enhanced readability. Refer to RFC 8628
         *   for guidance on minimal recommended entropy requirements for user code generation.
         */
        mask: '****-****',

        /*
         * features.deviceFlow.deviceInfo
         *
         * description: Specifies a helper function that shall be invoked to extract device-specific
         *   information from device authorization endpoint requests. The extracted information
         *   becomes available during the end-user confirmation screen to assist users in verifying
         *   that the authorization request originated from a device in their possession. This
         *   enhances security by enabling users to confirm device identity before granting authorization.
         */
        deviceInfo,
        /*
         * features.deviceFlow.userCodeInputSource
         *
         * description: Specifies the HTML source that shall be rendered when the device flow
         *   feature displays a user code input prompt to the User-Agent. This template is
         *   presented during the device authorization flow when the authorization server
         *   requires the end-user to enter a device-generated user code for verification.
         */
        userCodeInputSource,

        /*
         * features.deviceFlow.userCodeConfirmSource
         *
         * description: Specifies the HTML source that shall be rendered when the device flow
         *   feature displays a confirmation prompt to the User-Agent. This template is
         *   presented after successful user code validation to confirm the authorization
         *   request before proceeding with the device authorization flow.
         */
        userCodeConfirmSource,

        /*
         * features.deviceFlow.successSource
         *
         * description: Specifies the HTML source that shall be rendered when the device flow
         *   feature displays a success page to the User-Agent. This template is presented
         *   upon successful completion of the device authorization flow to inform the
         *   end-user that authorization has been granted to the requesting device.
         */
        successSource,
      },

      /*
       * features.encryption
       *
       * description: Specifies whether encryption capabilities shall be enabled.
       *   When enabled, the authorization server shall support accepting and issuing encrypted
       *   tokens involved in its other enabled capabilities.
       */
      encryption: { enabled: false },

      /*
       * features.fapi
       *
       * title: FAPI Security Profiles (`FAPI`)
       *
       * description: Specifies whether FAPI Security Profile capabilities shall be
       *   enabled. When enabled, the authorization server shall implement additional security
       *   behaviors defined in FAPI specifications that cannot be achieved through other
       *   configuration options.
       */
      fapi: {
        enabled: false,
        /*
         * features.fapi.profile
         *
         * description: Specifies the FAPI profile version that shall be applied for security
         *   policy enforcement. The authorization server shall implement the behaviors defined
         *   in the selected profile specification. Supported values include:
         *
         * - '2.0' - The authorization server shall implement behaviors from [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
         * - '1.0 Final' - The authorization server shall implement behaviors from [FAPI 1.0 Security Profile - Part 2: Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0-final.html)
         * - Function - A function that shall be invoked with arguments `(ctx, client)` to determine
         *   the profile contextually. The function shall return one of the supported profile values
         *   or undefined when FAPI behaviors should be ignored for the current request context.
         */
        profile: undefined,
      },

      /*
       * features.rpInitiatedLogout
       *
       * title: [`OIDC RP-Initiated Logout 1.0`](https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html)
       *
       * description: Specifies whether RP-Initiated Logout capabilities shall be enabled. When
       *   enabled, the authorization server shall support logout requests initiated by relying
       *   parties, allowing clients to request termination of end-user sessions.
       */
      rpInitiatedLogout: {
        enabled: true,

        /*
         * features.rpInitiatedLogout.postLogoutSuccessSource
         *
         * description: Specifies the HTML source that shall be rendered when an RP-Initiated
         *   Logout request concludes successfully but no `post_logout_redirect_uri` was provided
         *   by the requesting client. This template shall be presented to inform the end-user
         *   that the logout operation has completed successfully and provide appropriate
         *   post-logout guidance.
         */
        postLogoutSuccessSource,

        /*
         * features.rpInitiatedLogout.logoutSource
         *
         * description: Specifies the HTML source that shall be rendered when RP-Initiated Logout
         *   displays a confirmation prompt to the User-Agent. This template shall be presented
         *   to request explicit end-user confirmation before proceeding with the logout operation,
         *   ensuring user awareness and consent for session termination.
         */
        logoutSource,
      },

      /*
       * features.introspection
       *
       * title: [`RFC7662`](https://www.rfc-editor.org/rfc/rfc7662.html) - OAuth 2.0 Token Introspection
       *
       * description: Specifies whether OAuth 2.0 Token Introspection capabilities shall be enabled.
       *   When enabled, the authorization server shall expose a token introspection endpoint that
       *   allows authorized clients and resource servers to query the metadata and status of
       *   the following token types:
       *   - Opaque access tokens
       *   - Refresh tokens
       *
       */
      introspection: {
        enabled: false,

        /*
         * features.introspection.allowedPolicy
         *
         * description: Specifies a helper function that shall be invoked to determine whether
         *   the requesting client or resource server is authorized to introspect the specified
         *   token. This function enables enforcement of fine-grained access control policies
         *   for token introspection operations according to authorization server security requirements.
         */
        allowedPolicy: introspectionAllowedPolicy,
      },

      /*
       * features.jwtIntrospection
       *
       * title: [`RFC9701`](https://www.rfc-editor.org/rfc/rfc9701.html) - JWT Response for OAuth Token Introspection
       *
       * description: Specifies whether JWT-formatted token introspection responses shall be enabled.
       *   When enabled, the authorization server shall support issuing introspection responses
       *   as JSON Web Tokens, providing enhanced security and integrity protection for token
       *   metadata transmission between authorized parties.
       */
      jwtIntrospection: { enabled: false },

      /*
       * features.jwtResponseModes
       *
       * title: [JWT Secured Authorization Response Mode (`JARM`)](https://openid.net/specs/oauth-v2-jarm-errata1.html)
       *
       * description: Specifies whether JWT Secured Authorization Response Mode capabilities shall
       *   be enabled. When enabled, the authorization server shall support encoding authorization
       *   responses as JSON Web Tokens, providing cryptographic protection and integrity
       *   assurance for authorization response parameters.
       */
      jwtResponseModes: { enabled: false },

      /*
       * features.pushedAuthorizationRequests
       *
       * title: [`RFC9126`](https://www.rfc-editor.org/rfc/rfc9126.html) - OAuth 2.0 Pushed Authorization Requests (`PAR`)
       *
       * description: Specifies whether Pushed Authorization Request capabilities shall be enabled.
       *   When enabled, the authorization server shall expose a pushed authorization request endpoint
       *   that allows clients to lodge authorization request parameters at the authorization
       *   server prior to redirecting end-users to the authorization endpoint,
       *   enhancing security by removing the need to transmit parameters via query string parameters.
       */
      pushedAuthorizationRequests: {
        enabled: true,

        /*
         * features.pushedAuthorizationRequests.requirePushedAuthorizationRequests
         *
         * description: Specifies whether PAR usage shall be mandatory for all authorization
         *   requests as an authorization server security policy. When enabled, the authorization
         *   server shall reject authorization endpoint requests that do not utilize the pushed
         *   authorization request mechanism.
         */
        requirePushedAuthorizationRequests: false,

        /*
         * features.pushedAuthorizationRequests.allowUnregisteredRedirectUris
         *
         * description: Specifies whether unregistered redirect_uri values shall be permitted
         *   for authenticated clients using PAR that do not utilize a sector_identifier_uri.
         *   This configuration enables dynamic redirect URI specification within the security
         *   constraints of the pushed authorization request mechanism.
         */
        allowUnregisteredRedirectUris: false,
      },

      /*
       * features.registration
       *
       * title: [`OIDC Dynamic Client Registration 1.0`](https://openid.net/specs/openid-connect-registration-1_0-errata2.html) and [`RFC7591`](https://www.rfc-editor.org/rfc/rfc7591.html) - OAuth 2.0 Dynamic Client Registration Protocol
       *
       * description: Specifies whether Dynamic Client Registration capabilities shall be enabled.
       *   When enabled, the authorization server shall expose a client registration endpoint
       *   that allows clients to dynamically register themselves with the authorization server
       *   at runtime, enabling automated client onboarding and configuration management.
       */
      registration: {
        enabled: false,

        /*
         * features.registration.initialAccessToken
         *
         * description: Specifies whether the registration endpoint shall require an initial
         *   access token as authorization for client registration requests. This configuration
         *   controls access to the dynamic registration functionality. Supported values include:
         *   - `string` - The authorization server shall validate the provided bearer token
         *     against this static initial access token value
         *   - `boolean` - When true, the authorization server shall require adapter-backed
         *     initial access tokens; when false, registration requests are processed without
         *     initial access tokens.
         *
         * example: To add an adapter backed initial access token and retrive its value.
         *
         * ```js
         * new (provider.InitialAccessToken)({}).save().then(console.log);
         * ```
         */
        initialAccessToken: false,

        /*
         * features.registration.policies
         *
         * description: Specifies registration and registration management policies that shall be
         *   applied to client metadata properties during dynamic registration operations. Policies
         *   are synchronous or asynchronous functions assigned to Initial Access Tokens that
         *   execute before standard client property validations. Multiple policies may be assigned
         *   to an Initial Access Token, and by default, the same policies shall transfer to the
         *   Registration Access Token. Policy functions may throw errors to reject registration
         *   requests or modify the client properties object before validation.
         *
         * example: To define registration and registration management policies.
         *
         * To define policy functions configure `features.registration` to be an object like so:
         *
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
         * recommendation: Referenced policies MUST always be present when encountered on a token; an AssertionError
         * will be thrown inside the request context if a policy is not found, resulting in a 500 Server Error.
         *
         * recommendation: The same policies will be assigned to the Registration Access Token after a successful
         * validation. If you wish to assign different policies to the Registration Access Token:
         * ```js
         * // inside your final ran policy
         * ctx.oidc.entities.RegistrationAccessToken.policies = ['update-policy'];
         * ```
         */
        policies: undefined,

        /*
         * features.registration.idFactory
         *
         * description: Specifies a helper function that shall be invoked to generate random
         *   client identifiers during dynamic client registration operations. This function
         *   enables customization of client identifier generation according to authorization
         *   server requirements and conventions.
         */
        idFactory,

        /*
         * features.registration.secretFactory
         *
         * description: Specifies a helper function that shall be invoked to generate random
         *   client secrets during dynamic client registration operations. This function
         *   enables customization of client secret generation according to authorization
         *   server security requirements and entropy specifications.
         */
        secretFactory,

        /*
         * features.registration.issueRegistrationAccessToken
         *
         * description: Specifies whether a registration access token shall be issued upon
         *   successful client registration. This configuration determines if clients receive
         *   tokens for subsequent registration management operations. Supported values include:
         *   - `true` - Registration access tokens shall be issued for all successful registrations
         *   - `false` - Registration access tokens shall not be issued
         *   - Function - A function that shall be invoked to dynamically determine token issuance
         *     based on request context and authorization server policy
         *
         * example: To determine if a registration access token should be issued dynamically.
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
       * title: [`RFC7592`](https://www.rfc-editor.org/rfc/rfc7592.html) - OAuth 2.0 Dynamic Client Registration Management Protocol
       *
       * description: Specifies whether Dynamic Client Registration Management capabilities shall be enabled.
       *   When enabled, the authorization server shall expose Update and Delete operations as defined in RFC 7592,
       *   allowing clients to modify or remove their registration entries using Registration Access Tokens
       *   for client lifecycle management operations.
       */
      registrationManagement: {
        enabled: false,

        /*
         * features.registrationManagement.rotateRegistrationAccessToken
         *
         * description: Specifies whether registration access token rotation shall be enabled as a security
         *   policy for client registration management operations. When token rotation is active, the
         *   authorization server shall discard the current Registration Access Token upon successful
         *   update operations and issue a new token, returning it to the client with the Registration
         *   Update Response.
         *
         *   Supported values include:
         *   - `false` - Registration access tokens shall not be rotated and remain valid after use
         *   - `true` - Registration access tokens shall be rotated when used for management operations
         *   - Function - A function that shall be invoked to dynamically determine whether rotation
         *     should occur based on request context and authorization server policy
         *
         * example: Dynamic token rotation policy implementation.
         *
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
       * features.richAuthorizationRequests
       *
       * title: [`RFC9396`](https://www.rfc-editor.org/rfc/rfc9396.html) - OAuth 2.0 Rich Authorization Requests
       *
       * description: Specifies whether Rich Authorization Request capabilities shall be enabled.
       *   When enabled, the authorization server shall support the `authorization_details` parameter
       *   at the authorization and token endpoints to enable issuing Access Tokens with fine-grained
       *   authorization data and enhanced authorization scope control.
       */
      richAuthorizationRequests: {
        enabled: false,
        ack: undefined,
        /**
         * features.richAuthorizationRequests.types
         *
         * description: Specifies the authorization details type identifiers that shall be supported
         *   by the authorization server. Each type identifier MUST have an associated validation
         *   function that defines the required structure and constraints for authorization details
         *   of that specific type according to authorization server policy.
         *
         * example: Authorization details type validation for tax data access.
         *
         * ```js
         * import { z } from 'zod'
         *
         * const TaxData = z
         *   .object({
         *     duration_of_access: z.number().int().positive(),
         *     locations: z
         *       .array(
         *         z.literal('https://taxservice.govehub.no.example.com'),
         *       )
         *       .length(1),
         *     actions: z
         *       .array(z.literal('read_tax_declaration'))
         *       .length(1),
         *     periods: z
         *       .array(
         *         z.coerce
         *           .number()
         *           .max(new Date().getFullYear() - 1)
         *           .min(1997),
         *       )
         *       .min(1),
         *     tax_payer_id: z.string().min(1),
         *   })
         *   .strict()
         *
         * const configuration = {
         *   features: {
         *     richAuthorizationRequests: {
         *       enabled: true,
         *       // ...
         *       types: {
         *         tax_data: {
         *           validate(ctx, detail, client) {
         *             const { success: valid, error } =
         *               TaxData.parse(detail)
         *             if (!valid) {
         *               throw new InvalidAuthorizationDetails()
         *             }
         *           },
         *         },
         *       },
         *     },
         *   },
         * }
         * ```
         */
        types: {},
        /*
         * features.richAuthorizationRequests.rarForAuthorizationCode
         *
         * description: Specifies a helper function that shall be invoked to transform the requested
         *   and granted Rich Authorization Request details for storage in the authorization code.
         *   This function enables filtering and processing of authorization details according to
         *   authorization server policy before code persistence. The function shall return an
         *   array of authorization details or undefined.
         */
        rarForAuthorizationCode(ctx) {
          // decision points:
          // - ctx.oidc.client
          // - ctx.oidc.resourceServers
          // - ctx.oidc.params.authorization_details (unparsed authorization_details from the authorization request)
          // - ctx.oidc.grant.rar (authorization_details granted)
          mustChange('features.richAuthorizationRequests.rarForAuthorizationCode', 'transform the requested and granted RAR details to be passed in the authorization code');
          throw new Error(
            'features.richAuthorizationRequests.rarForAuthorizationCode not implemented',
          );
        },
        /*
         * features.richAuthorizationRequests.rarForCodeResponse
         *
         * description: Specifies a helper function that shall be invoked to transform the requested
         *   and granted Rich Authorization Request details for inclusion in the Access Token Response
         *   as authorization_details and assignment to the issued Access Token during the authorization code grant.
         *   This function enables
         *   resource-specific filtering and transformation of authorization details according to
         *   token endpoint policy. The function shall return an array of authorization details or undefined.
         */
        rarForCodeResponse(ctx, resourceServer) {
          // decision points:
          // - ctx.oidc.client
          // - resourceServer
          // - ctx.oidc.authorizationCode.rar (previously returned from rarForAuthorizationCode)
          // - ctx.oidc.params.authorization_details (unparsed authorization_details from the body params in the Access Token Request)
          // - ctx.oidc.grant.rar (authorization_details granted)
          mustChange('features.richAuthorizationRequests.rarForCodeResponse', 'transform the requested and granted RAR details to be returned in the Access Token Response as authorization_details as well as assigned to the issued Access Token');
          throw new Error(
            'features.richAuthorizationRequests.rarForCodeResponse not implemented',
          );
        },
        /*
         * features.richAuthorizationRequests.rarForBackchannelResponse
         *
         * description: Specifies a helper function that shall be invoked to transform the requested
         *   and granted Rich Authorization Request details for inclusion in the Access Token Response
         *   as authorization_details and assignment to the issued Access Token during the ciba grant.
         *   This function enables
         *   resource-specific filtering and transformation of authorization details according to
         *   token endpoint policy. The function shall return an array of authorization details or undefined.
         */
        rarForBackchannelResponse(ctx, resourceServer) {
          // decision points:
          // - ctx.oidc.client
          // - resourceServer
          // - ctx.oidc.entities.BackchannelAuthenticationRequest.rar (the rar applied during await provider.backchannelResult())
          // - ctx.oidc.entities.BackchannelAuthenticationRequest.params.authorization_details (the original backchannel authentication request authorization_details object)
          // - ctx.oidc.params.authorization_details (unparsed authorization_details from the body params in the Access Token Request)
          // - ctx.oidc.grant.rar (authorization_details granted)
          mustChange('features.richAuthorizationRequests.rarForBackchannelResponse', 'transform the requested and granted RAR details to be returned in the Access Token Response as authorization_details as well as assigned to the issued Access Token');
          throw new Error(
            'features.richAuthorizationRequests.rarForBackchannelResponse not implemented',
          );
        },
        /*
         * features.richAuthorizationRequests.rarForRefreshTokenResponse
         *
         * description: Specifies a helper function that shall be invoked to transform the requested
         *   and granted Rich Authorization Request details for inclusion in the Access Token Response
         *   during refresh token exchanges as authorization_details and assignment to the newly issued
         *   Access Token. This function enables resource-specific processing of previously granted
         *   authorization details according to refresh token policy. The function shall return an
         *   array of authorization details or undefined.
         */
        rarForRefreshTokenResponse(ctx, resourceServer) {
          // decision points:
          // - ctx.oidc.client
          // - resourceServer
          // - ctx.oidc.refreshToken.rar (previously returned from rarForAuthorizationCode and later assigned to the refresh token)
          // - ctx.oidc.params.authorization_details (unparsed authorization_details from the body params in the Access Token Request)
          // - ctx.oidc.grant.rar
          mustChange('features.richAuthorizationRequests.rarForRefreshTokenResponse', 'transform the requested and granted RAR details to be returned in the Access Token Response as authorization_details as well as assigned to the issued Access Token');
          throw new Error(
            'features.richAuthorizationRequests.rarForRefreshTokenResponse not implemented',
          );
        },
        /*
         * features.richAuthorizationRequests.rarForIntrospectionResponse
         *
         * description: Specifies a helper function that shall be invoked to transform the token's
         *   stored Rich Authorization Request details for inclusion in the Token Introspection Response.
         *   This function enables filtering and processing of authorization details according to
         *   introspection endpoint policy and requesting party authorization. The function shall
         *   return an array of authorization details or undefined.
         */
        rarForIntrospectionResponse(ctx, token) {
          // decision points:
          // - ctx.oidc.client
          // - token.kind
          // - token.rar
          // - ctx.oidc.grant.rar
          mustChange('features.richAuthorizationRequests.rarForIntrospectionResponse', 'transform the token\'s stored RAR details to be returned in the Introspection Response');
          throw new Error(
            'features.richAuthorizationRequests.rarForIntrospectionResponse not implemented',
          );
        },
      },

      /*
       * features.resourceIndicators
       *
       * title: [`RFC8707`](https://www.rfc-editor.org/rfc/rfc8707.html) - Resource Indicators for OAuth 2.0
       *
       * description: Specifies whether Resource Indicator capabilities shall be enabled. When
       *   enabled, the authorization server shall support the `resource` parameter at the
       *   authorization and token endpoints to enable issuing Access Tokens for specific
       *   Resource Servers (APIs) with enhanced audience control and scope management.
       *
       * The authorization server implements the following resource indicator processing rules:
       * - Multiple resource parameters may be present during Authorization Code Flow,
       * Device Authorization Grant, and Backchannel Authentication Requests,
       * but only a single audience for an Access Token is permitted.
       * - Authorization and Authentication Requests that result in an Access Token being issued by the
       * Authorization Endpoint MUST only contain a single resource (or one MUST be resolved using the
       * `defaultResource` helper).
       * - Client Credentials grant MUST only contain a single resource parameter.
       * - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request
       * exchanges, if the exchanged code/token does not include the `'openid'` scope and only has a single
       * resource then the resource parameter may be omitted - an Access Token for the single resource is
       * returned.
       * - During Authorization Code / Refresh Token / Device Code / Backchannel Authentication Request
       * exchanges, if the exchanged code/token does not include the `'openid'` scope and has multiple
       * resources then the resource parameter MUST be provided (or one MUST be resolved using the
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
       * - Issued Access Tokens shall always only contain scopes that are defined on the respective Resource
       * Server (returned from `features.resourceIndicators.getResourceServerInfo`).
       */
      resourceIndicators: {
        enabled: true,

        /*
         * features.resourceIndicators.defaultResource
         *
         * description: Specifies a helper function that shall be invoked to determine the default
         *   resource indicator for a request when none is provided by the client during the
         *   authorization request or when multiple resources are provided/resolved and only a
         *   single one is required during an Access Token Request. This function enables
         *   authorization server policy-based resource selection according to deployment requirements.
         */
        defaultResource,

        /*
         * features.resourceIndicators.useGrantedResource
         *
         * description: Specifies a helper function that shall be invoked to determine whether
         *   an already granted resource indicator should be used without being explicitly
         *   requested by the client during the Token Endpoint request. This function enables
         *   flexible resource selection policies for token issuance operations.
         *
         * recommendation: Use `return true` when it's allowed for a client to skip providing the "resource"
         *                 parameter at the Token Endpoint.
         * recommendation: Use `return false` (default) when it's required for a client to explicitly
         *                 provide a "resource" parameter at the Token Endpoint or when other indication
         *                 dictates an Access Token for the UserInfo Endpoint should be returned.
         */
        useGrantedResource,

        /*
         * features.resourceIndicators.getResourceServerInfo
         *
         * description: Specifies a helper function that shall be invoked to load information about
         *   a Resource Server (API) and determine whether the client is authorized to request
         *   scopes for that particular resource. This function enables resource-specific scope
         *   validation and Access Token configuration according to authorization server policy.
         *
         * recommendation: Only allow client's pre-registered resource values. To pre-register these
         *   you shall use the `extraClientMetadata` configuration option to define a custom metadata
         *   and use that to implement your policy using this function.
         *
         * example: Resource Server Definition.
         *
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
         *          alg?: string, // 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES384' | 'ES512' | 'Ed25519' | 'RS256' | 'RS384' | 'RS512' | 'EdDSA' | 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'
         *          kid?: string, // OPTIONAL `kid` to aid in signing key selection
         *        }
         *      | {
         *          alg: string, // 'HS256' | 'HS384' | 'HS512'
         *          key: CryptoKey | KeyObject | Buffer, // shared symmetric secret to sign the JWT token with
         *          kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWS Header
         *        },
         *     // Tokens will be encrypted
         *     encrypt?: {
         *       alg: string, // 'dir' | 'RSA-OAEP' | 'RSA-OAEP-256' | 'RSA-OAEP-384' | 'RSA-OAEP-512' | 'ECDH-ES' | 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW' | 'A128KW' | 'A192KW' | 'A256KW' | 'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW'
         *       enc: string, // 'A128CBC-HS256' | 'A128GCM' | 'A192CBC-HS384' | 'A192GCM' | 'A256CBC-HS512' | 'A256GCM'
         *       key: CryptoKey | KeyObject | Buffer, // public key or shared symmetric secret to encrypt the JWT token with
         *       kid?: string, // OPTIONAL `kid` JOSE Header Parameter to put in the token's JWE Header
         *     }
         *   }
         * }
         * ```
         *
         * example: Resource Server (API) with two scopes, an expected audience value, an Access Token TTL and a JWT Access Token Format.
         *
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
         *
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
         */
        getResourceServerInfo,
      },

      /*
       * features.requestObjects
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#RequestObject) and [`RFC9101`](https://www.rfc-editor.org/rfc/rfc9101.html#name-passing-a-request-object-by) - Passing a Request Object by Value (`JAR`)
       *
       * description: Specifies whether Request Object capabilities shall be enabled. When enabled,
       *   the authorization server shall support the use and validation of the `request` parameter
       *   for conveying authorization request parameters as JSON Web Tokens, providing enhanced
       *   security and integrity protection for authorization requests.
       */
      requestObjects: {
        enabled: false,

        /*
         * features.requestObjects.requireSignedRequestObject
         *
         * description: Specifies whether the use of signed request objects shall be mandatory for
         *   all authorization requests as an authorization server security policy. When enabled,
         *   the authorization server shall reject authorization requests that do not include a
         *   signed Request Object JWT.
         */
        requireSignedRequestObject: false,

        /**
         * features.requestObjects.assertJwtClaimsAndHeader
         *
         * description: Specifies a helper function that shall be invoked to perform additional
         *   validation of the Request Object JWT Claims Set and Header beyond the standard
         *   JAR specification requirements. This function enables enforcement of deployment-specific
         *   policies, security constraints, or extended validation logic according to authorization
         *   server requirements.
         */
        assertJwtClaimsAndHeader,
      },

      /*
       * features.rpMetadataChoices
       *
       * title: [`OIDC Relying Party Metadata Choices 1.0 - Implementers Draft 01`](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-ID1.html)
       *
       * description: Specifies whether Relying Party Metadata Choices capabilities shall be enabled.
       *   When enabled, the authorization server shall support the following multi-valued input
       *   parameters metadata from the Relying Party Metadata Choices draft, provided that their
       *   underlying feature is also enabled:
       *
       * - subject_types_supported
       * - id_token_signing_alg_values_supported
       * - id_token_encryption_alg_values_supported
       * - id_token_encryption_enc_values_supported
       * - userinfo_signing_alg_values_supported
       * - userinfo_encryption_alg_values_supported
       * - userinfo_encryption_enc_values_supported
       * - request_object_signing_alg_values_supported
       * - request_object_encryption_alg_values_supported
       * - request_object_encryption_enc_values_supported
       * - token_endpoint_auth_methods_supported
       * - token_endpoint_auth_signing_alg_values_supported
       * - introspection_signing_alg_values_supported
       * - introspection_encryption_alg_values_supported
       * - introspection_encryption_enc_values_supported
       * - authorization_signing_alg_values_supported
       * - authorization_encryption_alg_values_supported
       * - authorization_encryption_enc_values_supported
       * - backchannel_authentication_request_signing_alg_values_supported
       */
      rpMetadataChoices: { enabled: false, ack: undefined },

      /*
       * features.revocation
       *
       * title: [`RFC7009`](https://www.rfc-editor.org/rfc/rfc7009.html) - OAuth 2.0 Token Revocation
       *
       * description: Specifies whether Token Revocation capabilities shall be enabled. When enabled,
       *   the authorization server shall expose a token revocation endpoint that allows authorized
       *   clients and resource servers to notify the authorization server that a particular token
       *   is no longer needed. This feature supports revocation of the following token types:
       *   - Opaque access tokens
       *   - Refresh tokens
       *
       */
      revocation: {
        enabled: false,

        /*
         * features.revocation.allowedPolicy
         *
         * description: Specifies a helper function that shall be invoked to determine whether
         *   the requesting client or resource server is authorized to revoke the specified token.
         *   This function enables enforcement of fine-grained access control policies for token
         *   revocation operations according to authorization server security requirements.
         */
        allowedPolicy: revocationAllowedPolicy,
      },

      /*
       * features.userinfo
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfo) - UserInfo Endpoint
       *
       * description: Specifies whether the UserInfo Endpoint shall be enabled. When enabled,
       *   the authorization server shall expose a UserInfo endpoint that returns claims about
       *   the authenticated end-user. Access to this endpoint requires an opaque Access Token
       *   with at least `openid` scope that does not have a Resource Server audience.
       */
      userinfo: { enabled: true },

      /*
       * features.jwtUserinfo
       *
       * title: [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfo) - JWT UserInfo Endpoint Responses
       *
       * description: Specifies whether JWT-formatted UserInfo endpoint responses shall be enabled.
       *   When enabled, the authorization server shall support returning UserInfo responses as
       *   signed and/or encrypted JSON Web Tokens, providing enhanced security and integrity
       *   protection for end-user claims transmission. This feature shall also enable the
       *   relevant client metadata parameters for configuring JWT signing and/or encryption
       *   algorithms according to client requirements.
       */
      jwtUserinfo: { enabled: false },

      /*
       * features.webMessageResponseMode
       *
       * title: [draft-sakimura-oauth-wmrm-01](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-01) - OAuth 2.0 Web Message Response Mode
       *
       * description: Specifies whether Web Message Response Mode capabilities shall be enabled.
       *   When enabled, the authorization server shall support the `web_message` response mode
       *   for returning authorization responses via HTML5 Web Messaging. The implementation
       *   shall support only Simple Mode operation; authorization requests containing Relay Mode
       *   parameters will be rejected.
       *
       * recommendation: Although a general advise to use a `helmet` (e.g. for [express](https://www.npmjs.com/package/helmet),
       * [koa](https://www.npmjs.com/package/koa-helmet)) it is especially advised for your interaction
       * views routes if Web Message Response Mode is enabled in your deployment. You will have to experiment
       * with removal of the Cross-Origin-Embedder-Policy and Cross-Origin-Opener-Policy headers at various
       * endpoints throughout the authorization request end-user journey to finalize this feature.
       */
      webMessageResponseMode: { enabled: false, ack: undefined },

      /*
       * features.externalSigningSupport
       *
       * title: External Signing Support
       *
       * description: Specifies whether external signing capabilities shall be enabled. When enabled,
       *   the authorization server shall support the use of `ExternalSigningKey` class instances
       *   in place of private JWK entries within the `jwks.keys` configuration array. This feature
       *   enables Digital Signature Algorithm operations (such as PS256, ES256, or other supported
       *   algorithms) to be performed by external cryptographic services, including Key Management
       *   Services (KMS) and Hardware Security Modules (HSM), providing enhanced security for
       *   private key material through externalized signing operations.
       *
       * see: [KMS integration with AWS Key Management Service](https://github.com/panva/node-oidc-provider/discussions/1316)
       */
      externalSigningSupport: { enabled: false, ack: undefined },
    },

    /*
     * extraTokenClaims
     *
     * description: Specifies a helper function that shall be invoked to add additional claims
     *   to Access Tokens during the token issuance process. For opaque Access Tokens, the
     *   returned claims shall be stored in the authorization server storage under the `extra`
     *   property and shall be returned by the introspection endpoint as top-level claims.
     *   For JWT-formatted Access Tokens, the returned claims shall be included as top-level
     *   claims within the JWT payload. Claims returned by this function will not overwrite
     *   pre-existing top-level claims in the token.
     *
     * example: To add an arbitrary claim to an Access Token.
     *
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
       * description: Specifies the entropy configuration for opaque token generation. The value
       *   shall be an integer (or a function returning an integer) that determines the
       *   cryptographic strength of generated opaque tokens. The resulting opaque token length
       *   shall be calculated as `Math.ceil(i / Math.log2(n))` where `i` is the specified
       *   bit count and `n` is the number of symbols in the encoding alphabet (64 characters
       *   in the base64url character set used by this implementation).
       *
       * example: To have e.g. Refresh Tokens values longer than Access Tokens.
       *
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
       * description: Specifies customizer functions that shall be invoked immediately before
       *   issuing structured Access Tokens to enable modification of token headers and payload
       *   claims according to authorization server policy. These functions shall be called
       *   during the token formatting process to apply deployment-specific customizations
       *   to the token structure before signing.
       *
       * example: To push additional headers and payload claims to a `jwt` format Access Token.
       *
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
     * expiresWithSession
     *
     * description: Specifies a helper function that shall be invoked to determine whether
     *   authorization codes, device codes, or authorization-endpoint-returned opaque access
     *   tokens shall be bound to the end-user session. When session binding is enabled, this
     *   policy shall be applied to all opaque tokens issued from the authorization code, device
     *   code, or subsequent refresh token exchanges. When artifacts are session-bound, their
     *   originating session will be loaded by its unique identifier every time the artifacts
     *   are encountered. Session-bound artifacts shall be effectively revoked when the end-user
     *   logs out, providing automatic cleanup of token state upon session termination.
     */
    expiresWithSession,

    /*
     * issueRefreshToken
     *
     * description: Specifies a helper function that shall be invoked to determine whether
     *   a refresh token shall be issued during token endpoint operations. This function
     *   enables policy-based control over refresh token issuance according to authorization
     *   server requirements, client capabilities, and granted scope values.
     *
     * example: To always issue a refresh token (cont.)
     *
     * (cont.) if a client has the grant allowed and scope includes offline_access or the client is a
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
     * description: Specifies the JSON Web Key Set that shall be used by the authorization server
     *   for cryptographic signing and decryption operations. The key set MUST be provided in
     *   [JWK Set format](https://www.rfc-editor.org/rfc/rfc7517.html#section-5) as defined in
     *   RFC 7517. All keys within the set MUST be private keys.
     *
     * Supported key types include:
     *
     * - RSA
     * - OKP (Ed25519 and X25519 sub types)
     * - EC (P-256, P-384, and P-521 curves)
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
    jwks: undefined,

    /*
     * responseTypes
     *
     * description: Specifies the response_type values supported by this authorization server.
     *   In accordance with RFC 9700 (OAuth 2.0 Security Best Current Practice), the default
     *   configuration excludes response types that result in access tokens being issued directly
     *   by the authorization endpoint.
     *
     * example: Supported values list.
     *
     * These are values defined in [`OIDC Core 1.0`](https://openid.net/specs/openid-connect-core-1_0-errata2.html#Authentication)
     * and [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0-final.html)
     * ```js
     * [
     *   'code',
     *   'id_token', 'id_token token',
     *   'code id_token', 'code token', 'code id_token token',
     *   'none',
     * ]
     * ```
     */
    responseTypes: ['code id_token', 'code', 'id_token', 'none'],

    /*
     * pkce
     *
     * title: [`RFC7636`](https://www.rfc-editor.org/rfc/rfc7636.html) - Proof Key for Code Exchange (`PKCE`)
     *
     * description: `PKCE` configuration such as policy check on the required use of `PKCE`.
     *
     * @nodefault
     */
    pkce: {
      /*
       * pkce.required
       *
       * description: Configures if and when the authorization server requires clients to use `PKCE`. This helper is called
       * whenever an authorization request lacks the code_challenge parameter.
       * Return:
       *   - `false` to allow the request to continue without `PKCE`
       *   - `true` to abort the request
       */
      required: pkceRequired,
    },

    /*
     * routes
     *
     * description: Defines the URL path mappings for authorization server endpoints.
     *   All route values are relative and shall begin with a forward slash ("/") character.
     */
    routes: {
      authorization: '/auth',
      backchannel_authentication: '/backchannel',
      code_verification: '/device',
      challenge: '/challenge',
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
     * description: Specifies additional OAuth 2.0 scope values that this authorization server
     *   shall support and advertise in its discovery document. Resource Server-specific
     *   scopes shall be configured via the `features.resourceIndicators` mechanism.
     */
    scopes: ['openid', 'offline_access'],

    /*
     * subjectTypes
     *
     * description: Specifies the array of Subject Identifier types that this authorization server
     *   shall support for end-user identification purposes. When only `pairwise` is supported,
     *   it shall become the default `subject_type` client metadata value. Supported identifier
     *   types shall include:
     *   - `public` - provides the same subject identifier value to all clients
     *   - `pairwise` - provides a unique subject identifier value per client to enhance privacy
     */
    subjectTypes: ['public'],

    /*
     * pairwiseIdentifier
     *
     * description: Specifies a helper function that shall be invoked to generate pairwise subject
     *   identifier values for ID Tokens and UserInfo responses, as specified in OpenID Connect
     *   Core 1.0. This function enables privacy-preserving subject identifier generation that
     *   provides unique identifiers per client while maintaining consistent identification for
     *   the same end-user across requests to the same client.
     *
     * recommendation: Implementations should employ memoization or caching mechanisms when
     *   this function may be invoked multiple times with identical arguments within a single request.
     */
    pairwiseIdentifier,

    /*
     * clientAuthMethods
     *
     * description: Specifies the client authentication methods that this authorization server
     *   shall support for authenticating clients at the token endpoint and other authenticated
     *   endpoints.
     *
     * example: Supported values list.
     *
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
     * description: Specifies the Time-To-Live (TTL) values that shall be applied to various
     *   artifacts within the authorization server. TTL values may be specified
     *   as either a numeric value (in seconds) or a synchronous function that returns a
     *   numeric value based on the current request context and authorization server policy.
     *
     * recommendation: Token TTL values should be set to the minimum duration necessary for
     *   the intended use case to minimize security exposure.
     *
     * recommendation: For refresh tokens requiring extended lifetimes, consider utilizing the
     *   `rotateRefreshToken` configuration option, which extends effective token lifetime through
     *   rotation rather than extended initial TTL values.
     *
     * example: To resolve a ttl on runtime for each new token.
     *
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
     * description: Specifies the configuration for custom client metadata properties that shall
     *   be supported by the authorization server for client registration and metadata validation purposes.
     *   This configuration enables extension of standard OAuth 2.0 and OpenID Connect client
     *   metadata with deployment-specific properties. Existing standards-defined properties are snakeCased on
     *   a Client instance (e.g. `client.redirectUris`), while new properties defined by this
     *   configuration shall be available with their names verbatim (e.g.
     *   `client['urn:example:client:my-property']`).
     * @nodefault
     */
    extraClientMetadata: {
      /*
       * extraClientMetadata.properties
       *
       * description: Specifies an array of property names that clients shall be allowed to have
       *   defined within their client metadata during registration and management operations.
       *   Each property name listed here extends the standard client metadata schema according
       *   to authorization server policy.
       */
      properties: [],
      /*
       * extraClientMetadata.validator
       *
       * description: Specifies a validator function that shall be executed in order once for every
       *   property defined in `extraClientMetadata.properties`, regardless of its value or presence
       *   in the client metadata passed during registration or update operations. The function MUST
       *   be synchronous; async validators or functions returning Promise shall be rejected during
       *   runtime. To modify the current client metadata values (for the current key or any other)
       *   simply modify the passed in `metadata` argument within the validator function.
       */
      validator: extraClientMetadataValidator,
    },

    /*
     * renderError
     *
     * description: Specifies a function that shall be invoked to present error responses to the
     *   User-Agent during authorization server operations. This function enables customization
     *   of error presentation according to deployment-specific user interface requirements.
     */
    renderError,

    /*
     * revokeGrantPolicy
     *
     * description: Specifies a helper function that shall be invoked to determine whether an
     *   underlying Grant entry shall be revoked in addition to the specific token or code being
     *   processed. This function enables enforcement of grant revocation policies according to
     *   authorization server security requirements. The function is invoked in the following
     *   contexts:
     * - RP-Initiated Logout
     * - Opaque Access Token Revocation
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
     * description: Specifies a function that shall be invoked to determine whether the
     *   sectorIdentifierUri of a client being loaded, registered, or updated should be fetched
     *   and its contents validated against the client metadata.
     */
    sectorIdentifierUriValidate,

    /*
     * interactions
     *
     * description: Specifies the configuration for interaction policy and end-user redirection
     *   that shall be applied to determine that user interaction
     *   is required during the authorization process. This configuration enables customization
     *   of authentication and consent flows according to deployment-specific requirements.
     *
     * @nodefault
     */
    interactions: {
      /*
       * interactions.policy
       *
       * description: Specifies the structure of Prompts and their associated checks that shall
       *   be applied during authorization request processing. The policy is formed by Prompt
       *   and Check class instances that define the conditions under which user interaction
       *   is required. The default policy implementation provides a fresh instance that can
       *   be customized, and the relevant classes are exported for configuration purposes.
       *
       * example: default interaction policy description.
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
       * example: disabling default consent checks.
       *
       * You may be required to skip (silently accept) some of the consent checks, while it is
       * discouraged there are valid reasons to do that, for instance in some first-party scenarios or
       * going with pre-existing, previously granted, consents. To simply silenty "accept"
       * first-party/resource indicated scopes or pre-agreed-upon claims use the `loadExistingGrant`
       * configuration helper function, in there you may just instantiate (and save!) a grant for the
       * current clientId and accountId values.
       *
       * example: modifying the default interaction policy.
       *
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
       * description: Specifies a function that shall be invoked to determine the destination URL
       *   for redirecting the User-Agent when user interaction is required during authorization
       *   processing. This function enables customization of the interaction endpoint location
       *   and may return both absolute and relative URLs according to deployment requirements.
       */
      url: interactionsUrl,
    },

    /*
     * findAccount
     *
     * description: Specifies a function that shall be invoked to load an account and retrieve
     *   its available claims during authorization server operations. This function enables
     *   the authorization server to resolve end-user account information based on the provided
     *   account identifier. The function MUST return a Promise that resolves to an account
     *   object containing an `accountId` property and a `claims()` method that returns an
     *   object with claims corresponding to the claims supported by the issuer. The `claims()`
     *   method may also return a Promise that shall be resolved or rejected according to
     *   account availability and authorization server policy.
     */
    findAccount,

    /*
     * rotateRefreshToken
     *
     * description: Specifies the refresh token rotation policy that shall be applied by the
     *   authorization server when refresh tokens are used.
     *   This configuration determines whether and under what conditions refresh tokens shall
     *   be rotated. Supported values
     *   include:
     *   - `false` - refresh tokens shall not be rotated and their initial expiration date is final
     *   - `true` - refresh tokens shall be rotated when used, with the current token marked as
     *     consumed and a new one issued with new TTL; when a consumed refresh token is
     *     encountered an error shall be returned and the whole token chain (grant) is revoked
     *   - `function` - a function returning true/false that shall be invoked to determine
     *     whether rotation should occur based on request context and authorization server policy
     *
     * <br/><br/>
     *
     * The default configuration value implements a sensible refresh token rotation policy that:
     *   - only allows refresh tokens to be rotated (have their TTL prolonged by issuing a new one) for one year
     *   - otherwise always rotates public client tokens that are not sender-constrained
     *   - otherwise only rotates tokens if they're being used close to their expiration (>= 70% TTL passed)
     */
    rotateRefreshToken,

    /*
     * enabledJWA
     *
     * description: Specifies the JSON Web Algorithm (JWA) values supported by this authorization
     *   server for various cryptographic operations, as defined in RFC 7518 and related specifications.
     * @nodefault
     */
    enabledJWA: {
      /*
       * enabledJWA.clientAuthSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports for signed JWT Client Authentication
       * (`private_key_jwt` and `client_secret_jwt`)
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      clientAuthSigningAlgValues: [
        'HS256',
        'RS256',
        'PS256',
        'ES256',
        'Ed25519',
        'EdDSA',
      ],

      /*
       * enabledJWA.idTokenSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports to sign ID Tokens with.
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      idTokenSigningAlgValues: ['RS256', 'PS256', 'ES256', 'Ed25519', 'EdDSA'],

      /*
       * enabledJWA.requestObjectSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports to receive signed Request Objects (`JAR`) with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      requestObjectSigningAlgValues: [
        'HS256',
        'RS256',
        'PS256',
        'ES256',
        'Ed25519',
        'EdDSA',
      ],

      /*
       * enabledJWA.userinfoSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports to sign UserInfo responses with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      userinfoSigningAlgValues: ['RS256', 'PS256', 'ES256', 'Ed25519', 'EdDSA'],

      /*
       * enabledJWA.introspectionSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports to sign JWT Introspection responses with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      introspectionSigningAlgValues: [
        'RS256',
        'PS256',
        'ES256',
        'Ed25519',
        'EdDSA',
      ],

      /*
       * enabledJWA.authorizationSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports to sign JWT Authorization Responses (`JARM`) with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       *   'HS256', 'HS384', 'HS512',
       * ]
       * ```
       */
      authorizationSigningAlgValues: [
        'RS256',
        'PS256',
        'ES256',
        'Ed25519',
        'EdDSA',
      ],

      /*
       * enabledJWA.idTokenEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the authorization server supports for ID Token encryption
       *
       * example: Supported values list.
       *
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
        'A128KW',
        'A256KW',
        'ECDH-ES',
        'RSA-OAEP',
        'RSA-OAEP-256',
        'dir',
      ],

      /*
       * enabledJWA.requestObjectEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the authorization server supports to receive encrypted Request Objects (`JAR`) with
       *
       * example: Supported values list.
       *
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
        'A128KW',
        'A256KW',
        'ECDH-ES',
        'RSA-OAEP',
        'RSA-OAEP-256',
        'dir',
      ],

      /*
       * enabledJWA.userinfoEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the authorization server supports for UserInfo Response encryption
       *
       * example: Supported values list.
       *
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
        'A128KW',
        'A256KW',
        'ECDH-ES',
        'RSA-OAEP',
        'RSA-OAEP-256',
        'dir',
      ],

      /*
       * enabledJWA.introspectionEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the authorization server supports for JWT Introspection response
       * encryption
       *
       * example: Supported values list.
       *
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
        'A128KW',
        'A256KW',
        'ECDH-ES',
        'RSA-OAEP',
        'RSA-OAEP-256',
        'dir',
      ],

      /*
       * enabledJWA.authorizationEncryptionAlgValues
       *
       * description: JWE "alg" Algorithm values the authorization server supports for JWT Authorization response (`JARM`)
       * encryption
       *
       * example: Supported values list.
       *
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
        'A128KW',
        'A256KW',
        'ECDH-ES',
        'RSA-OAEP',
        'RSA-OAEP-256',
        'dir',
      ],

      /*
       * enabledJWA.idTokenEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt ID Tokens with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      idTokenEncryptionEncValues: [
        'A128CBC-HS256',
        'A128GCM',
        'A256CBC-HS512',
        'A256GCM',
      ],

      /*
       * enabledJWA.requestObjectEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to decrypt Request Objects (`JAR`) with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      requestObjectEncryptionEncValues: [
        'A128CBC-HS256',
        'A128GCM',
        'A256CBC-HS512',
        'A256GCM',
      ],

      /*
       * enabledJWA.userinfoEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt UserInfo responses with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      userinfoEncryptionEncValues: [
        'A128CBC-HS256',
        'A128GCM',
        'A256CBC-HS512',
        'A256GCM',
      ],

      /*
       * enabledJWA.introspectionEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt JWT Introspection responses with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      introspectionEncryptionEncValues: [
        'A128CBC-HS256',
        'A128GCM',
        'A256CBC-HS512',
        'A256GCM',
      ],

      /*
       * enabledJWA.authorizationEncryptionEncValues
       *
       * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt JWT Authorization Responses (`JARM`) with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
       * ]
       * ```
       */
      authorizationEncryptionEncValues: [
        'A128CBC-HS256',
        'A128GCM',
        'A256CBC-HS512',
        'A256GCM',
      ],

      /*
       * enabledJWA.dPoPSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports to verify signed DPoP proof JWTs with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       * ]
       * ```
       */
      dPoPSigningAlgValues: ['ES256', 'Ed25519', 'EdDSA'],

      /*
       * enabledJWA.attestSigningAlgValues
       *
       * description: JWS "alg" Algorithm values the authorization server supports to verify signed Client Attestation and Client Attestation PoP JWTs with
       *
       * example: Supported values list.
       *
       * ```js
       * [
       *   'RS256', 'RS384', 'RS512',
       *   'PS256', 'PS384', 'PS512',
       *   'ES256', 'ES384', 'ES512',
       *   'Ed25519', 'EdDSA',
       *   'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', // available in Node.js >= 24.7.0
       * ]
       * ```
       */
      attestSigningAlgValues: ['ES256', 'Ed25519', 'EdDSA'],
    },

    /*
     * assertJwtClientAuthClaimsAndHeader
     *
     * description: Specifies a helper function that shall be invoked to perform additional
     *   validation of JWT Client Authentication assertion Claims Set and Header beyond the
     *   requirements mandated by the specification. This function enables enforcement of
     *   deployment-specific security policies and extended validation logic for `private_key_jwt`
     *   and `client_secret_jwt` client authentication methods according to authorization
     *   server requirements.
     */
    assertJwtClientAuthClaimsAndHeader,

    /*
     * fetch
     *
     * description: Specifies a function that shall be invoked whenever the authorization server
     *   needs to make calls to external HTTPS resources. The interface and expected return
     *   value shall conform to the [Fetch API specification](https://fetch.spec.whatwg.org/)
     *   [`fetch()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/fetch) standard.
     *   The default implementation uses a timeout of 2500ms and does not send a user-agent header.
     *
     * example: To change the request's timeout.
     *
     * To change all request's timeout configure the fetch as a function like so:
     *
     * ```js
     *  {
     *    fetch(url, options) {
     *      options.signal = AbortSignal.timeout(5000);
     *      return globalThis.fetch(url, options);
     *    }
     *  }
     * ```
     */
    fetch,

    /*
     * enableHttpPostMethods
     *
     * description: Specifies whether HTTP POST method support shall be enabled at the
     *   Authorization Endpoint and the Logout Endpoint (if enabled). When enabled, the
     *   authorization server shall accept POST requests at these endpoints in addition
     *   to the standard GET requests. This configuration may only be used when the
     *   `cookies.long.sameSite` configuration value is `none`.
     */
    enableHttpPostMethods: false,
  };

  return defaults;
}

export default makeDefaults;
export const defaults = makeDefaults();
