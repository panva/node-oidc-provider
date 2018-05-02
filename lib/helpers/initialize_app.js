const Router = require('koa-router');
const getCors = require('kcors');
const attention = require('./attention');
const instance = require('./weak_cache');
const { InvalidRequest } = require('./errors');

const getAuthorization = require('../actions/authorization');
const getUserinfo = require('../actions/userinfo');
const getToken = require('../actions/token');
const getCertificates = require('../actions/certificates');
const getRegistration = require('../actions/registration');
const getRevocation = require('../actions/revocation');
const getIntrospection = require('../actions/introspection');
const getWebfinger = require('../actions/webfinger');
const getDiscovery = require('../actions/discovery');
const getCheckSession = require('../actions/check_session');
const getEndSession = require('../actions/end_session');
const getInteraction = require('../actions/interaction');
const grants = require('../actions/grants');
const responseModes = require('../response_modes');

const getResumeMiddleware = require('../shared/resume');
const getSessionMiddleware = require('../shared/session');
const error = require('../shared/error_handler');
const getAuthError = require('../shared/authorization_error_handler');
const invalidRoute = require('../shared/invalid_route');
const contextEnsureOidc = require('../shared/context_ensure_oidc');

const webfingerRoute = '/.well-known/webfinger';
const discoveryRoute = '/.well-known/openid-configuration';

module.exports = function initializeApp() {
  const configuration = instance(this).configuration();
  const { app } = instance(this);

  const router = new Router();
  instance(this).router = router;

  const get = router.get.bind(router);
  const post = router.post.bind(router);
  const del = router.del.bind(router);
  const put = router.put.bind(router);
  const options = router.options.bind(router);

  const { routes } = configuration;
  const onlyGetCors = getCors({ allowedMethods: 'GET' });

  Object.entries(grants).forEach(([grantType, { handler, parameters }]) => {
    if (configuration.grantTypes.has(grantType)) {
      this.registerGrantType(grantType, handler, parameters);
    }
  });

  ['query', 'fragment', 'form_post'].forEach((mode) => {
    this.registerResponseMode(mode, responseModes[mode]);
  });

  const session = getSessionMiddleware(this);
  const authError = getAuthError(this);

  const authorization = getAuthorization(this);
  get('authorization', routes.authorization, authError, session, authorization);
  post('authorization', routes.authorization, authError, session, authorization);

  const resume = getResumeMiddleware(this);
  get('resume', `${routes.authorization}/:grant`, authError, session, resume, authorization);

  const userinfo = getUserinfo(this);
  const userInfoCors = getCors({ allowedMethods: 'GET,POST' });
  get('userinfo', routes.userinfo, userInfoCors, userinfo);
  post('userinfo', routes.userinfo, userInfoCors, userinfo);
  options('userinfo', routes.userinfo, userInfoCors);

  const token = getToken(this);
  post('token', routes.token, error(this, 'grant.error'), token);

  const certificates = getCertificates(this);
  get('certificates', routes.certificates, onlyGetCors, error(this, 'certificates.error'), certificates);
  options('certificates', routes.certificates, onlyGetCors);

  if (configuration.features.registration) {
    const registration = getRegistration(this);
    const clientRoute = `${routes.registration}/:clientId`;

    post('registration', routes.registration, error(this, 'registration_create.error'), registration.post);
    get('client', clientRoute, error(this, 'registration_read.error'), registration.get);

    if (configuration.features.registrationManagement) {
      put('client_update', clientRoute, error(this, 'registration_update.error'), registration.put);
      del('client_delete', clientRoute, error(this, 'registration_delete.error'), registration.delete);
    }
  }

  if (configuration.features.revocation) {
    const revocation = getRevocation(this);
    post('revocation', routes.revocation, error(this, 'revocation.error'), revocation);
  }

  if (configuration.features.introspection) {
    const introspection = getIntrospection(this);
    post('introspection', routes.introspection, error(this, 'introspection.error'), introspection);
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
    const checkFrame = getCheckSession(this);
    get('check_session', routes.check_session, error(this, 'check_session.error'), checkFrame);

    const endSession = getEndSession(this);
    get('end_session', routes.end_session, error(this, 'end_session.error'), session, endSession.get);
    post('end_session', routes.end_session, error(this, 'end_session.error'), session, endSession.post);
  }

  if (configuration.features.devInteractions) {
    const interaction = getInteraction(this);

    get('interaction', '/interaction/:grant', error(this), interaction.get);
    post('submit', '/interaction/:grant/submit', error(this), interaction.post);
  }

  async function proxyWarning(ctx, next) {
    if (proxyWarning.pass) return next();

    if (!ctx.secure && ctx.get('x-forwarded-proto') === 'https') {
      attention.warn('x-forwarded-proto header detected but not trusted, you must set proxy=true on the koa application, see documentation for more details');
      proxyWarning.pass = true;
    }

    return next();
  }
  proxyWarning.firstInternal = true;

  app.use(proxyWarning);
  app.use(contextEnsureOidc(this));
  app.use(router.routes());
  app.use(error(this));
  app.use(invalidRoute);

  const allowedMethodsMiddleware = router.allowedMethods({
    throw: true,
    methodNotAllowed: () => new InvalidRequest('method not allowed', 405),
    notImplemented: () => new InvalidRequest('not implemented', 501),
  });
  app.use(async (ctx, next) => {
    try {
      await allowedMethodsMiddleware(ctx, next);
    } catch (err) {
      if (err.statusCode === 405) {
        err.error_description = `method ${ctx.method} not allowed on ${ctx.path}`;
      }
      throw err;
    }
  });
};
