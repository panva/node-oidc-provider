import { strict as assert } from 'node:assert';

import Router from '@koa/router';

import devInteractions from '../actions/interaction.js';
import cors from '../shared/cors.js';
import * as grants from '../actions/grants/index.js';
import * as responseModes from '../response_modes/index.js';
import error from '../shared/error_handler.js';
import getAuthError from '../shared/authorization_error_handler.js';
import {
  getAuthorization, userinfo, getToken, jwks, registration, getRevocation,
  getIntrospection, discovery, endSession, codeVerification, challenge,
} from '../actions/index.js';

import als from './als.js';
import instance from './weak_cache.js';

export default function initializeApp() {
  const { configuration, features } = instance(this);
  const maxAge = 3600;
  function exposeHeaders({
    dpop = features.dPoP.enabled && features.dPoP.nonceSecret,
    attest = features.attestClientAuth.enabled,
    wwwAuth = true,
  } = {}) {
    return [
      dpop ? 'DPoP-Nonce' : undefined,
      attest ? 'OAuth-Client-Attestation-Challenge' : undefined,
      wwwAuth ? 'WWW-Authenticate' : undefined,
    ].filter(Boolean);
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
    respond: () => {},
  };

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
    route = route.replace(/\/\//g, '/'); // eslint-disable-line no-param-reassign
    stack.forEach((middleware) => assert.equal(typeof middleware, 'function'), 'invalid middleware');
    routeMap.set(name, route);
    return route;
  }
  async function ensureSessionSave(ctx, next) {
    try {
      await next();
    } finally {
      if (ctx.oidc.session?.touched && !ctx.oidc.session.destroyed) {
        await ctx.oidc.session.persist();
      }
    }
  }

  const get = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack); // eslint-disable-line no-param-reassign
    router.get(name, route, ensureOIDC, ensureSessionSave, ...stack);
  };
  const post = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack); // eslint-disable-line no-param-reassign
    router.post(name, route, ensureOIDC, ensureSessionSave, ...stack);
  };
  const del = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack); // eslint-disable-line no-param-reassign
    router.delete(name, route, ensureOIDC, ...stack);
  };
  const put = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack); // eslint-disable-line no-param-reassign
    router.put(name, route, ensureOIDC, ...stack);
  };
  const options = (name, route, ...stack) => {
    route = normalizeRoute(name, route, ...stack); // eslint-disable-line no-param-reassign
    router.options(name, route, ensureOIDC, ...stack);
  };

  const { routes, enableHttpPostMethods } = configuration;

  for (const { handler, parameters, grantType } of Object.values(grants)) {
    const { grantTypeHandlers } = instance(this);
    if (configuration.grantTypes.has(grantType) && !grantTypeHandlers.has(grantType)) {
      let dupes;
      if (features.resourceIndicators.enabled) {
        parameters.add('resource');
        dupes = new Set(['resource']);
      }
      if (features.richAuthorizationRequests.enabled) {
        parameters.add('authorization_details');
      }
      this.registerGrantType(grantType, handler, parameters, dupes);
    }
  }

  ['query', 'fragment', 'form_post'].forEach((mode) => {
    this.registerResponseMode(mode, responseModes[mode]);
  });

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

  const authorization = getAuthorization(this, 'authorization');
  const authError = getAuthError(this);
  get('authorization', routes.authorization, authError, ...authorization);
  if (enableHttpPostMethods) {
    post('authorization', routes.authorization, authError, ...authorization);
  }

  const resume = getAuthorization(this, 'resume');
  get('resume', `${routes.authorization}/:uid`, authError, ...resume);

  if (features.userinfo.enabled) {
    get('userinfo', routes.userinfo, CORS.userinfo, error(this, 'userinfo.error'), ...userinfo);
    post('userinfo', routes.userinfo, CORS.userinfo, error(this, 'userinfo.error'), ...userinfo);
    options('cors.userinfo', routes.userinfo, CORS.userinfo, CORS.respond);
  }

  const token = getToken(this);
  post('token', routes.token, error(this, 'grant.error'), CORS.clientWithDPoP, ...token);
  options('cors.token', routes.token, CORS.clientWithDPoP, CORS.respond);

  get('jwks', routes.jwks, CORS.open, error(this, 'jwks.error'), jwks);
  options('cors.jwks', routes.jwks, CORS.open, CORS.respond);

  const oauthDiscoveryRoute = '/.well-known/oauth-authorization-server';
  get('discovery', oauthDiscoveryRoute, CORS.open, error(this, 'discovery.error'), discovery);
  options('cors.discovery', oauthDiscoveryRoute, CORS.open, CORS.respond);

  const openidDiscoveryRoute = '/.well-known/openid-configuration';
  get('discovery', openidDiscoveryRoute, CORS.open, error(this, 'discovery.error'), discovery);
  options('cors.discovery', openidDiscoveryRoute, CORS.open, CORS.respond);

  if (features.attestClientAuth.enabled) {
    post('challenge', routes.challenge, error(this, 'challenge.error'), CORS.challenge, ...challenge);
    options('cors.challenge', routes.challenge, CORS.challenge, CORS.respond);
  }

  if (features.registration.enabled) {
    const clientRoute = `${routes.registration}/:clientId`;

    post('registration', routes.registration, error(this, 'registration_create.error'), ...registration.post);
    get('client', clientRoute, error(this, 'registration_read.error'), ...registration.get);

    if (features.registrationManagement.enabled) {
      put('client_update', clientRoute, error(this, 'registration_update.error'), ...registration.put);
      del('client_delete', clientRoute, error(this, 'registration_delete.error'), ...registration.del);
    }
  }

  if (features.revocation.enabled) {
    const revocation = getRevocation(this);
    post('revocation', routes.revocation, error(this, 'revocation.error'), CORS.client, ...revocation);
    options('cors.revocation', routes.revocation, CORS.client, CORS.respond);
  }

  if (features.introspection.enabled) {
    const introspection = getIntrospection(this);
    post('introspection', routes.introspection, error(this, 'introspection.error'), CORS.client, ...introspection);
    options('cors.introspection', routes.introspection, CORS.client, CORS.respond);
  }

  post('end_session_confirm', `${routes.end_session}/confirm`, error(this, 'end_session_confirm.error'), ...endSession.confirm);

  if (features.rpInitiatedLogout.enabled) {
    if (enableHttpPostMethods) {
      post('end_session', routes.end_session, error(this, 'end_session.error'), ...endSession.init);
    }
    get('end_session', routes.end_session, error(this, 'end_session.error'), ...endSession.init);
    get('end_session_success', `${routes.end_session}/success`, error(this, 'end_session_success.error'), ...endSession.success);
  }

  if (features.deviceFlow.enabled) {
    const deviceAuthorization = getAuthorization(this, 'device_authorization');
    post('device_authorization', routes.device_authorization, error(this, 'device_authorization.error'), CORS.client, ...deviceAuthorization);
    options('cors.device_authorization', routes.device_authorization, CORS.client, CORS.respond);

    const postCodeVerification = getAuthorization(this, 'code_verification');
    get('code_verification', routes.code_verification, error(this, 'code_verification.error'), ...codeVerification.get);
    post('code_verification', routes.code_verification, error(this, 'code_verification.error'), ...codeVerification.post, ...postCodeVerification);

    const deviceResume = getAuthorization(this, 'device_resume');
    get('device_resume', `${routes.code_verification}/:uid`, error(this, 'device_resume.error'), ...deviceResume);
  }

  if (features.pushedAuthorizationRequests.enabled) {
    const pushedAuthorizationRequests = getAuthorization(this, 'pushed_authorization_request');
    post('pushed_authorization_request', routes.pushed_authorization_request, error(this, 'pushed_authorization_request.error'), CORS.clientWithDPoP, ...pushedAuthorizationRequests);
    options('cors.pushed_authorization_request', routes.pushed_authorization_request, CORS.clientWithDPoP, CORS.respond);
  }

  if (features.ciba.enabled) {
    const ciba = getAuthorization(this, 'backchannel_authentication');
    post('backchannel_authentication', routes.backchannel_authentication, error(this, 'backchannel_authentication.error'), ...ciba);
  }

  if (features.devInteractions.enabled) {
    const interaction = devInteractions(this);

    get('interaction', '/interaction/:uid', error(this), ...interaction.render);
    post('submit', '/interaction/:uid', error(this), ...interaction.submit);
    get('abort', '/interaction/:uid/abort', error(this), ...interaction.abort);
  }

  return router.routes();
}
