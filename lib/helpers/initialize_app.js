const assert = require('assert');
const querystring = require('querystring');

const getCors = require('@koa/cors');

const Router = require('../router');
const { homepage, version } = require('../../package.json');
const {
  getAuthorization, getUserinfo, getToken, getCertificates, getRegistration, getRevocation,
  getIntrospection, getWebfinger, getDiscovery, getCheckSession, getEndSession, getCodeVerification,
} = require('../actions');
const getInteraction = require('../actions/interaction');
const grants = require('../actions/grants');
const responseModes = require('../response_modes');
const error = require('../shared/error_handler');
const getAuthError = require('../shared/authorization_error_handler');
const contextEnsureOidc = require('../shared/context_ensure_oidc');

const { InvalidRequest } = require('./errors');
const instance = require('./weak_cache');
const attention = require('./attention');
const { ROUTER_URL_METHOD } = require('./symbols');

const webfingerRoute = '/.well-known/webfinger';
const discoveryRoute = '/.well-known/openid-configuration';
const pkceGrants = new Set(['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code']);

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
    stack.forEach(middleware => assert.deepEqual(typeof middleware, 'function'), 'invalid middleware');
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
  const onlyGetCors = getCors({ allowMethods: 'GET' });

  Object.entries(grants).forEach(([grantType, { handler, parameters }]) => {
    const { grantTypeHandlers } = instance(this);
    if (configuration.grantTypes.has(grantType) && !grantTypeHandlers.has(grantType)) {
      let dupes;
      if (configuration.features.pkce && pkceGrants.has(grantType)) {
        parameters.add('code_verifier');
      }
      if (configuration.features.resourceIndicators) {
        parameters.add('resource');
        dupes = new Set(['resource']);
      }
      this.registerGrantType(grantType, handler, parameters, dupes);
    }
  });

  ['query', 'fragment', 'form_post'].forEach((mode) => {
    this.registerResponseMode(mode, responseModes[mode]);
  });

  if (configuration.features.webMessageResponseMode) {
    this.registerResponseMode('web_message', responseModes.webMessage);
  }

  if (configuration.features.jwtResponseModes) {
    this.registerResponseMode('jwt', responseModes.jwt);

    ['query', 'fragment', 'form_post'].forEach((mode) => {
      this.registerResponseMode(`${mode}.jwt`, responseModes.jwt);
    });

    if (configuration.features.webMessageResponseMode) {
      this.registerResponseMode('web_message.jwt', responseModes.jwt);
    }
  }

  const authorization = getAuthorization(this, 'authorization');
  const authError = getAuthError(this);
  get('authorization', routes.authorization, authError, ...authorization);
  post('authorization', routes.authorization, authError, ...authorization);

  const resume = getAuthorization(this, 'resume');
  get('resume', `${routes.authorization}/:grant`, authError, ...resume);

  const userinfo = getUserinfo(this);
  const userInfoCors = getCors({
    allowMethods: 'GET,POST', exposeHeaders: 'WWW-Authenticate', allowHeaders: 'Authorization',
  });
  get('userinfo', routes.userinfo, userInfoCors, error(this, 'userinfo.error'), ...userinfo);
  post('userinfo', routes.userinfo, userInfoCors, error(this, 'userinfo.error'), ...userinfo);
  options('userinfo', routes.userinfo, userInfoCors);

  const token = getToken(this);
  post('token', routes.token, error(this, 'grant.error'), ...token);

  const certificates = getCertificates(this);
  get('certificates', routes.certificates, onlyGetCors, error(this, 'certificates.error'), certificates);
  options('certificates', routes.certificates, onlyGetCors);

  if (configuration.features.registration) {
    const registration = getRegistration(this);
    const clientRoute = `${routes.registration}/:clientId`;

    post('registration', routes.registration, error(this, 'registration_create.error'), ...registration.post);
    get('client', clientRoute, error(this, 'registration_read.error'), ...registration.get);

    if (configuration.features.registrationManagement) {
      put('client_update', clientRoute, error(this, 'registration_update.error'), ...registration.put);
      del('client_delete', clientRoute, error(this, 'registration_delete.error'), ...registration.delete);
    }
  }

  if (configuration.features.revocation) {
    const revocation = getRevocation(this);
    post('revocation', routes.revocation, error(this, 'revocation.error'), ...revocation);
  }

  if (configuration.features.introspection) {
    const introspection = getIntrospection(this);
    post('introspection', routes.introspection, error(this, 'introspection.error'), ...introspection);
  }

  if (configuration.features.discovery) {
    const webfinger = getWebfinger(this);
    get('webfinger', webfingerRoute, onlyGetCors, error(this, 'webfinger.error'), webfinger);
    options('webfinger', webfingerRoute, onlyGetCors);

    const discovery = getDiscovery(this);
    get('discovery', discoveryRoute, onlyGetCors, error(this, 'discovery.error'), discovery);
    options('discovery', discoveryRoute, onlyGetCors);
  }

  if (configuration.features.sessionManagement) {
    const checkSession = getCheckSession(this);
    get('check_session', routes.check_session, error(this, 'check_session.error'), checkSession.get);
    post('check_session_origin', routes.check_session, error(this, 'check_session_origin.error'), ...checkSession.post);
  }

  if (
    configuration.features.sessionManagement
    || configuration.features.backchannelLogout
    || configuration.features.frontchannelLogout
  ) {
    const endSession = getEndSession(this);
    get('end_session', routes.end_session, error(this, 'end_session.error'), ...endSession.get);
    post('end_session', routes.end_session, error(this, 'end_session.error'), ...endSession.post);
  }

  if (configuration.features.deviceFlow) {
    const deviceAuthorization = getAuthorization(this, 'device_authorization');
    post('device_authorization', routes.device_authorization, error(this, 'device_authorization.error'), ...deviceAuthorization);

    const codeVerification = getCodeVerification(this);
    const postCodeVerification = getAuthorization(this, 'code_verification');
    get('code_verification', routes.code_verification, error(this, 'code_verification.error'), ...codeVerification.get);
    post('code_verification', routes.code_verification, error(this, 'code_verification.error'), ...codeVerification.post, ...postCodeVerification);

    const deviceResume = getAuthorization(this, 'device_resume');
    get('device_resume', `${routes.code_verification}/:user_code/:grant`, error(this, 'device_resume.error'), ...deviceResume);
  }

  if (configuration.features.devInteractions) {
    const interaction = getInteraction(this);

    get('interaction', '/interaction/:grant', error(this), ...interaction.get);
    post('submit', '/interaction/:grant/submit', error(this), ...interaction.post);
  }

  const { issuer } = this;
  async function proxyWarning(ctx, next) {
    if (proxyWarning.pass) return next();

    if (issuer.startsWith('https:') && !ctx.secure && ctx.get('x-forwarded-proto') === 'https') {
      attention.warn(`x-forwarded-proto header detected but not trusted, you must set proxy=true on the provider, see documentation for more details (${homepage}/blob/${version}/docs/configuration.md#trusting-tls-offloading-proxies)`);
      proxyWarning.pass = true;
    } else if (issuer.startsWith('https:') && !ctx.secure && !ctx.get('x-forwarded-proto')) {
      attention.warn(`x-forwarded-proto header not detected for an https issuer, you must configure your ssl offloading proxy and the provider, see documentation for more details (${homepage}/blob/${version}/docs/configuration.md#trusting-tls-offloading-proxies)`);
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
