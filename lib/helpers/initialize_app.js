const { strict: assert } = require('assert');
const querystring = require('querystring');

const Router = require('../router');
const {
  getAuthorization, userinfo, getToken, jwks, registration, getRevocation,
  getIntrospection, discovery, checkSession, endSession, codeVerification,
} = require('../actions');
const getInteraction = require('../actions/interaction');
const cors = require('../shared/cors');
const grants = require('../actions/grants');
const responseModes = require('../response_modes');
const error = require('../shared/error_handler');
const getAuthError = require('../shared/authorization_error_handler');
const contextEnsureOidc = require('../shared/context_ensure_oidc');

const docs = require('./docs');
const { InvalidRequest } = require('./errors');
const instance = require('./weak_cache');
const attention = require('./attention');
const { ROUTER_URL_METHOD } = require('./symbols');

const discoveryRoute = '/.well-known/openid-configuration';
const CORS_AUTHORIZATION = { exposeHeaders: 'WWW-Authenticate', maxAge: 3600 };
const CORS = {
  open: cors({ allowMethods: 'GET', maxAge: 3600 }),
  userinfo: cors({ allowMethods: 'GET,POST', clientBased: true, ...CORS_AUTHORIZATION }),
  client: cors({ allowMethods: 'POST', clientBased: true, ...CORS_AUTHORIZATION }),
};

module.exports = function initializeApp() {
  const configuration = instance(this).configuration();
  const { app } = instance(this);

  const router = new Router();
  instance(this).router = router;

  const ensureOIDC = contextEnsureOidc(this);

  const routeMap = new Map();
  function routerAssert(name, route, ...stack) {
    assert(typeof name === 'string' && name.charAt(0) !== '/', `invalid route name ${name}`);
    assert(typeof route === 'string' && route.charAt(0) === '/', `invalid route ${route}`);
    stack.forEach((middleware) => assert.equal(typeof middleware, 'function'), 'invalid middleware');
    routeMap.set(name, route);
  }
  async function ensureSessionSave(ctx, next) {
    try {
      await next();
    } finally {
      if (ctx.oidc.session && ctx.oidc.session.touched && !ctx.oidc.session.destroyed) {
        await ctx.oidc.session.save();
      }
    }
  }
  function namedRoute(name, ctx, next) {
    ctx._matchedRouteName = name;
    return next();
  }

  router[ROUTER_URL_METHOD] = function routeUrl(name, opts = {}) {
    let path = routeMap.get(name);

    if (!path) {
      throw new Error(`No route found for name: ${name}`);
    }

    Object.entries(opts).forEach(([key, value]) => {
      path = path.replace(`:${key}`, value);
    });

    if ('query' in opts) {
      path = `${path}?${querystring.stringify(opts.query)}`;
    }

    return path;
  };

  const get = (name, route, ...stack) => {
    routerAssert(name, route, ...stack);
    router.get(route, namedRoute.bind(undefined, name), ensureOIDC, ensureSessionSave, ...stack);
  };
  const post = (name, route, ...stack) => {
    routerAssert(name, route, ...stack);
    router.post(route, namedRoute.bind(undefined, name), ensureOIDC, ensureSessionSave, ...stack);
  };
  const del = (name, route, ...stack) => {
    routerAssert(name, route, ...stack);
    router.delete(route, namedRoute.bind(undefined, name), ensureOIDC, ...stack);
  };
  const put = (name, route, ...stack) => {
    routerAssert(name, route, ...stack);
    router.put(route, namedRoute.bind(undefined, name), ensureOIDC, ...stack);
  };
  const options = (name, route, ...stack) => {
    routerAssert(name, route, ...stack);
    router.options(route, namedRoute.bind(undefined, name), ensureOIDC, ...stack);
  };

  const { routes } = configuration;

  Object.entries(grants).forEach(([grantType, { handler, parameters }]) => {
    const { grantTypeHandlers } = instance(this);
    if (configuration.grantTypes.has(grantType) && !grantTypeHandlers.has(grantType)) {
      let dupes;
      if (grantType === 'authorization_code') {
        parameters.add('code_verifier');
      }
      if (configuration.features.resourceIndicators.enabled) {
        parameters.add('resource');
        dupes = new Set(['resource']);
      }
      this.registerGrantType(grantType, handler, parameters, dupes);
    }
  });

  ['query', 'fragment', 'form_post'].forEach((mode) => {
    this.registerResponseMode(mode, responseModes[mode]);
  });

  if (configuration.features.webMessageResponseMode.enabled) {
    this.registerResponseMode('web_message', responseModes.webMessage);
  }

  if (configuration.features.jwtResponseModes.enabled) {
    this.registerResponseMode('jwt', responseModes.jwt);

    ['query', 'fragment', 'form_post'].forEach((mode) => {
      this.registerResponseMode(`${mode}.jwt`, responseModes.jwt);
    });

    if (configuration.features.webMessageResponseMode.enabled) {
      this.registerResponseMode('web_message.jwt', responseModes.jwt);
    }
  }

  const authorization = getAuthorization(this, 'authorization');
  const authError = getAuthError(this);
  get('authorization', routes.authorization, authError, ...authorization);
  post('authorization', routes.authorization, authError, ...authorization);

  const resume = getAuthorization(this, 'resume');
  get('resume', `${routes.authorization}/:uid`, authError, ...resume);

  if (configuration.features.userinfo.enabled) {
    get('userinfo', routes.userinfo, CORS.userinfo, error(this, 'userinfo.error'), ...userinfo);
    post('userinfo', routes.userinfo, CORS.userinfo, error(this, 'userinfo.error'), ...userinfo);
    options('cors.userinfo', routes.userinfo, CORS.userinfo);
  }

  const token = getToken(this);
  post('token', routes.token, error(this, 'grant.error'), CORS.client, ...token);
  options('cors.token', routes.token, CORS.client);

  get('jwks', routes.jwks, CORS.open, error(this, 'jwks.error'), jwks);
  options('cors.jwks', routes.jwks, CORS.open);

  get('discovery', discoveryRoute, CORS.open, error(this, 'discovery.error'), discovery);
  options('cors.discovery', discoveryRoute, CORS.open);

  if (configuration.features.registration.enabled) {
    const clientRoute = `${routes.registration}/:clientId`;

    post('registration', routes.registration, error(this, 'registration_create.error'), ...registration.post);
    get('client', clientRoute, error(this, 'registration_read.error'), ...registration.get);

    if (configuration.features.registrationManagement.enabled) {
      put('client_update', clientRoute, error(this, 'registration_update.error'), ...registration.put);
      del('client_delete', clientRoute, error(this, 'registration_delete.error'), ...registration.delete);
    }
  }

  if (configuration.features.revocation.enabled) {
    const revocation = getRevocation(this);
    post('revocation', routes.revocation, error(this, 'revocation.error'), CORS.client, ...revocation);
    options('cors.revocation', routes.revocation, CORS.client);
  }

  if (configuration.features.introspection.enabled) {
    const introspection = getIntrospection(this);
    post('introspection', routes.introspection, error(this, 'introspection.error'), CORS.client, ...introspection);
    options('cors.introspection', routes.introspection, CORS.client);
  }

  if (configuration.features.sessionManagement.enabled) {
    get('check_session', routes.check_session, error(this, 'check_session.error'), checkSession.get);
    post('check_session_origin', routes.check_session, error(this, 'check_session_origin.error'), ...checkSession.post);
  }

  get('end_session', routes.end_session, error(this, 'end_session.error'), ...endSession.init);
  post('end_session', routes.end_session, error(this, 'end_session.error'), ...endSession.init);
  post('end_session_confirm', `${routes.end_session}/confirm`, error(this, 'end_session_confirm.error'), ...endSession.confirm);
  get('end_session_success', `${routes.end_session}/success`, error(this, 'end_session_success.error'), ...endSession.success);

  if (configuration.features.deviceFlow.enabled) {
    const deviceAuthorization = getAuthorization(this, 'device_authorization');
    post('device_authorization', routes.device_authorization, error(this, 'device_authorization.error'), CORS.client, ...deviceAuthorization);
    options('cors.device_authorization', routes.device_authorization, CORS.client);

    const postCodeVerification = getAuthorization(this, 'code_verification');
    get('code_verification', routes.code_verification, error(this, 'code_verification.error'), ...codeVerification.get);
    post('code_verification', routes.code_verification, error(this, 'code_verification.error'), ...codeVerification.post, ...postCodeVerification);

    const deviceResume = getAuthorization(this, 'device_resume');
    get('device_resume', `${routes.code_verification}/:user_code/:uid`, error(this, 'device_resume.error'), ...deviceResume);
  }

  if (configuration.features.pushedRequestObjects.enabled) {
    const pushedRequestObjects = getAuthorization(this, 'request_object');
    post('request_object', routes.request_object, error(this, 'request_object.error'), CORS.client, ...pushedRequestObjects);
    options('cors.request_object', routes.request_object, CORS.client);
  }

  if (configuration.features.devInteractions.enabled) {
    const interaction = getInteraction(this);

    get('interaction', '/interaction/:uid', error(this), ...interaction.render);
    post('submit', '/interaction/:uid', error(this), ...interaction.submit);
    get('abort', '/interaction/:uid/abort', error(this), ...interaction.abort);
  }

  const { issuer } = this;
  async function proxyWarning(ctx, next) {
    if (proxyWarning.pass) return next();

    if (issuer.startsWith('https:') && !ctx.secure && ctx.get('x-forwarded-proto') === 'https') {
      attention.warn(`x-forwarded-proto header detected but not trusted, you must set proxy=true on the provider, see documentation for more details: ${docs('trusting-tls-offloading-proxies')}`);
      proxyWarning.pass = true;
    } else if (issuer.startsWith('https:') && !ctx.secure && !ctx.get('x-forwarded-proto')) {
      attention.warn(`x-forwarded-proto header not detected for an https issuer, you must configure your ssl offloading proxy and the provider, see documentation for more details: ${docs('trusting-tls-offloading-proxies')}`);
      proxyWarning.pass = true;
    }

    return next();
  }
  proxyWarning.firstInternal = true;

  app.use(proxyWarning);
  app.use(error(this));
  app.use(async (ctx, next) => {
    await next();
    if (ctx.status === 404 && ctx.message === 'Not Found') {
      throw new InvalidRequest(`unrecognized route or not allowed method (${ctx.method} on ${ctx.path})`, 404);
    }
  });
  app.use(router.routes());
};
