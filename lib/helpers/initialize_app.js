import { strict as assert } from 'node:assert';

import Router from './router.js';

import * as devInteractions from '../actions/interaction.js';
import cors from '../shared/cors.js';
import * as grants from '../actions/grants/index.js';
import * as responseModes from '../response_modes/index.js';
import error from '../shared/error_handler.js';
import authError from '../shared/authorization_error_handler.js';
import {
  getAuthorization, userinfo, token, jwks, registration, revocation,
  introspection, discovery, endSession, codeVerification, challenge,
  openidCredentialIssuer, credential,
} from '../actions/index.js';

import als from './als.js';
import * as grantHelpers from './grants.js';
import instance from './weak_cache.js';

const maxAge = 3600;
function exposeHeaders({
  dpop = true,
  attest = true,
  wwwAuth = true,
} = {}) {
  return (ctx) => {
    const { features } = instance(ctx.oidc.provider);
    return [
      dpop && features.dPoP.enabled && features.dPoP.nonceSecret ? 'DPoP-Nonce' : undefined,
      attest && features.attestClientAuth.enabled ? 'OAuth-Client-Attestation-Challenge' : undefined,
      wwwAuth ? 'WWW-Authenticate' : undefined,
    ].filter(Boolean);
  };
}

const CORS = {
  open: cors({ allowMethods: 'GET', maxAge }),
  challenge: cors({ allowMethods: 'POST', maxAge, exposeHeaders: exposeHeaders({ wwwAuth: false }) }),
  userinfo: cors({
    allowMethods: 'GET,POST', clientBased: true, maxAge, exposeHeaders: exposeHeaders({ attest: false }),
  }),
  client: cors({
    allowMethods: 'POST', clientBased: true, maxAge, exposeHeaders: exposeHeaders({ dpop: false }),
  }),
  clientWithDPoP: cors({
    allowMethods: 'POST', clientBased: true, maxAge, exposeHeaders: exposeHeaders(),
  }),
  credential: cors({
    allowMethods: 'POST', clientBased: true, maxAge, exposeHeaders: exposeHeaders({ attest: false }),
  }),
  respond: () => {},
};

async function ensureSessionSave(ctx, next) {
  try {
    await next();
  } finally {
    if (ctx.oidc.session?.touched && !ctx.oidc.session.destroyed) {
      await ctx.oidc.session.persist();
    }
  }
}

export default function initializeApp() {
  const { configuration, features } = instance(this);

  const router = new Router();
  instance(this).router = router;

  const ensureOIDC = async (ctx, next) => {
    let oidcCtx;
    Object.defineProperty(ctx, 'oidc', {
      get: () => {
        oidcCtx ||= new this.OIDCContext(ctx);
        return oidcCtx;
      },
    });
    return als.run(ctx, () => next());
  };

  const routeMap = new Map();
  function normalizeRoute(name, route, ...stack) {
    assert(typeof name === 'string' && name.charAt(0) !== '/', `invalid route name ${name}`);
    assert(typeof route === 'string' && route.charAt(0) === '/', `invalid route ${route}`);
    route = route.replace(/\/\//g, '/');
    stack.forEach((middleware) => { assert.equal(typeof middleware, 'function', 'invalid middleware'); });
    routeMap.set(name, route);
    return route;
  }

  const get = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack);
    router.get(name, route, ensureOIDC, ensureSessionSave, ...stack);
  };
  const post = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack);
    router.post(name, route, ensureOIDC, ensureSessionSave, ...stack);
  };
  const del = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack);
    router.delete(name, route, ensureOIDC, ...stack);
  };
  const put = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack);
    router.put(name, route, ensureOIDC, ...stack);
  };
  const options = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack);
    router.options(name, route, ensureOIDC, ...stack);
  };

  const { routes, enableHttpPostMethods } = configuration;
  const boundGrantHelpers = Object.fromEntries(
    Object.entries(grantHelpers).map(([name, helper]) => [name, helper.bind(undefined, this)]),
  );

  for (const { handler, parameters, grantType } of Object.values(grants)) {
    const { grantTypeHandlers } = instance(this);
    if (configuration.grantTypes.has(grantType) && !grantTypeHandlers.has(grantType)) {
      const grantParameters = new Set(parameters);
      let dupes;
      if (features.resourceIndicators.enabled) {
        grantParameters.add('resource');
        dupes = new Set(['resource']);
      }
      if (features.richAuthorizationRequests.enabled) {
        grantParameters.add('authorization_details');
      }
      this.registerGrantType(
        grantType,
        handler.bind(undefined, this, boundGrantHelpers),
        grantParameters,
        dupes,
      );
    }
  }

  this.registerResponseMode('query', responseModes.query);
  this.registerResponseMode('fragment', responseModes.fragment);
  this.registerResponseMode('form_post', responseModes.form_post);

  if (features.webMessageResponseMode.enabled) {
    this.registerResponseMode('web_message', responseModes.webMessage);
  }

  if (features.jwtResponseModes.enabled) {
    this.registerResponseMode('jwt', responseModes.jwt);

    ['query', 'fragment', 'form_post'].forEach((mode) => {
      this.registerResponseMode(`${mode}.jwt`, responseModes.jwt);
    });

    if (features.webMessageResponseMode.enabled) {
      this.registerResponseMode('web_message.jwt', responseModes.jwt);
    }
  }

  const authorization = getAuthorization('authorization');
  get('authorization', routes.authorization, authError, ...authorization);
  if (enableHttpPostMethods) {
    post('authorization', routes.authorization, authError, ...authorization);
  }

  const resume = getAuthorization('resume');
  get('resume', `${routes.authorization}/:uid`, authError, ...resume);

  if (features.userinfo.enabled) {
    get('userinfo', routes.userinfo, CORS.userinfo, error('userinfo.error'), ...userinfo);
    post('userinfo', routes.userinfo, CORS.userinfo, error('userinfo.error'), ...userinfo);
    options('cors.userinfo', routes.userinfo, CORS.userinfo, CORS.respond);
  }

  post('token', routes.token, error('grant.error'), CORS.clientWithDPoP, ...token);
  options('cors.token', routes.token, CORS.clientWithDPoP, CORS.respond);

  get('jwks', routes.jwks, CORS.open, error('jwks.error'), jwks);
  options('cors.jwks', routes.jwks, CORS.open, CORS.respond);

  const oauthDiscoveryRoute = '/.well-known/oauth-authorization-server';
  get('discovery', oauthDiscoveryRoute, CORS.open, error('discovery.error'), discovery);
  options('cors.discovery', oauthDiscoveryRoute, CORS.open, CORS.respond);

  const openidDiscoveryRoute = '/.well-known/openid-configuration';
  get('discovery', openidDiscoveryRoute, CORS.open, error('discovery.error'), discovery);
  options('cors.discovery', openidDiscoveryRoute, CORS.open, CORS.respond);

  if (features.openid4vci.enabled) {
    const credentialIssuerRoute = '/.well-known/openid-credential-issuer';
    get('openid_credential_issuer', credentialIssuerRoute, CORS.open, error('openid_credential_issuer.error'), openidCredentialIssuer);
    options('cors.openid_credential_issuer', credentialIssuerRoute, CORS.open, CORS.respond);

    post('credential', routes.credential, error('credential.error'), CORS.credential, ...credential);
    options('cors.credential', routes.credential, CORS.credential, CORS.respond);
  }

  if (features.attestClientAuth.enabled || features.openid4vci.enabled) {
    post('challenge', routes.challenge, error('challenge.error'), CORS.challenge, ...challenge);
    options('cors.challenge', routes.challenge, CORS.challenge, CORS.respond);
  }

  if (features.registration.enabled) {
    const clientRoute = `${routes.registration}/:clientId`;

    post('registration', routes.registration, error('registration_create.error'), ...registration.post);
    get('client', clientRoute, error('registration_read.error'), ...registration.get);

    if (features.registrationManagement.enabled) {
      put('client_update', clientRoute, error('registration_update.error'), ...registration.put);
      del('client_delete', clientRoute, error('registration_delete.error'), ...registration.del);
    }
  }

  if (features.revocation.enabled) {
    post('revocation', routes.revocation, error('revocation.error'), CORS.client, ...revocation);
    options('cors.revocation', routes.revocation, CORS.client, CORS.respond);
  }

  if (features.introspection.enabled) {
    post('introspection', routes.introspection, error('introspection.error'), CORS.client, ...introspection);
    options('cors.introspection', routes.introspection, CORS.client, CORS.respond);
  }

  post('end_session_confirm', `${routes.end_session}/confirm`, error('end_session_confirm.error'), ...endSession.confirm);

  if (features.rpInitiatedLogout.enabled) {
    if (enableHttpPostMethods) {
      post('end_session', routes.end_session, error('end_session.error'), ...endSession.init);
    }
    get('end_session', routes.end_session, error('end_session.error'), ...endSession.init);
    get('end_session_success', `${routes.end_session}/success`, error('end_session_success.error'), ...endSession.success);
  }

  if (features.deviceFlow.enabled) {
    const deviceAuthorization = getAuthorization('device_authorization');
    post('device_authorization', routes.device_authorization, error('device_authorization.error'), CORS.client, ...deviceAuthorization);
    options('cors.device_authorization', routes.device_authorization, CORS.client, CORS.respond);

    const postCodeVerification = getAuthorization('code_verification');
    get('code_verification', routes.code_verification, error('code_verification.error'), ...codeVerification.get);
    post('code_verification', routes.code_verification, error('code_verification.error'), ...codeVerification.post, ...postCodeVerification);

    const deviceResume = getAuthorization('device_resume');
    get('device_resume', `${routes.code_verification}/:uid`, error('device_resume.error'), ...deviceResume);
  }

  if (features.pushedAuthorizationRequests.enabled) {
    const pushedAuthorizationRequests = getAuthorization('pushed_authorization_request');
    post('pushed_authorization_request', routes.pushed_authorization_request, error('pushed_authorization_request.error'), CORS.clientWithDPoP, ...pushedAuthorizationRequests);
    options('cors.pushed_authorization_request', routes.pushed_authorization_request, CORS.clientWithDPoP, CORS.respond);
  }

  if (features.ciba.enabled) {
    const ciba = getAuthorization('backchannel_authentication');
    post('backchannel_authentication', routes.backchannel_authentication, error('backchannel_authentication.error'), ...ciba);
  }

  if (features.devInteractions.enabled) {
    devInteractions.initialize(this);

    get('interaction', '/interaction/:uid', error(), ...devInteractions.render);
    post('submit', '/interaction/:uid', error(), ...devInteractions.submit);
    get('abort', '/interaction/:uid/abort', error(), ...devInteractions.abort);
  }

  return router.routes();
}
