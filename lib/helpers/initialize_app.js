'use strict';

const Koa = require('koa');
const path = require('path');
const render = require('koa-ejs');
const co = require('co');
const Router = require('koa-router');
const getCors = require('kcors');
const instance = require('./weak_cache');
const errors = require('./errors');

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
  const app = new Koa();

  instance(this).app = app;

  const router = new Router();
  instance(this).router = router;

  const get = router.get.bind(router);
  const post = router.post.bind(router);
  const del = router.del.bind(router);
  const put = router.put.bind(router);
  const options = router.options.bind(router);

  const routes = configuration.routes;
  const onlyGetCors = getCors({ allowedMethods: 'GET' });

  configuration.grantTypes.forEach((grantType) => {
    try {
      const grant = require(`../actions/token/${grantType}`); // eslint-disable-line global-require, import/no-dynamic-require
      this.registerGrantType(grantType, grant.handler, grant.parameters);
    } catch (err) {
      /* istanbul ignore if */
      if (err.code !== 'MODULE_NOT_FOUND') throw err;
    }
  });

  const session = getSessionMiddleware(this);
  const authError = getAuthError(this);

  const authorization = getAuthorization(this);
  get('authorization', routes.authorization, authError, session, authorization);
  post(routes.authorization, authError, session, authorization);

  const resume = getResumeMiddleware(this);
  get('resume', `${routes.authorization}/:grant`, authError, session, resume, authorization);

  const userinfo = getUserinfo(this);
  const userInfoCors = getCors({ allowedMethods: 'GET,POST' });
  get('userinfo', routes.userinfo, userInfoCors, userinfo);
  post(routes.userinfo, userInfoCors, userinfo);
  options(routes.userinfo, userInfoCors);

  const token = getToken(this);
  post('token', routes.token, error(this, 'grant.error'), token);

  const certificates = getCertificates(this);
  get('certificates', routes.certificates, onlyGetCors, error(this, 'certificates.error'),
  certificates);
  options(routes.certificates, onlyGetCors);

  if (configuration.features.registration) {
    const registration = getRegistration(this);
    const clientRoute = `${routes.registration}/:clientId`;

    post('registration', routes.registration, error(this, 'registration_create.error'),
    registration.post);
    get('registration_client', clientRoute, error(this, 'registration_read.error'),
    registration.get);

    if (configuration.features.registrationManagement) {
      put(clientRoute, error(this, 'registration_update.error'), registration.put);
      del(clientRoute, error(this, 'registration_delete.error'), registration.delete);
    }
  }

  if (configuration.features.revocation) {
    const revocation = getRevocation(this);
    post('revocation', routes.revocation, error(this, 'revocation.error'), revocation);
  }

  if (configuration.features.introspection) {
    const introspection = getIntrospection(this);
    post('introspection', routes.introspection, error(this, 'introspection.error'),
    introspection);
  }

  if (configuration.features.discovery) {
    const webfinger = getWebfinger(this);
    get('webfinger', webfingerRoute, onlyGetCors, error(this, 'webfinger.error'), webfinger);
    options(webfingerRoute, onlyGetCors);

    const discovery = getDiscovery(this);
    get('discovery', discoveryRoute, onlyGetCors, error(this, 'discovery.error'), discovery);
    options(discoveryRoute, onlyGetCors);
  }

  if (configuration.features.sessionManagement) {
    const checkFrame = getCheckSession(this);
    get('check_session', routes.check_session, error(this, 'check_session.error'), checkFrame);

    const endSession = getEndSession(this);
    get('end_session', routes.end_session, error(this, 'end_session.error'), session,
    endSession.get);
    post(routes.end_session, error(this, 'end_session.error'), session, endSession.post);
  }

  if (configuration.features.devInteractions) {
    const interaction = getInteraction(this);
    render(app, {
      cache: false,
      layout: '_layout',
      root: path.join(__dirname, '..', 'views'),
    });
    app.context.render = co.wrap(app.context.render);

    get('/interaction/:grant', error(this), interaction.get);
    post('interaction', '/interaction/:grant/submit', error(this), interaction.post);
  }

  app.use(contextEnsureOidc(this));
  app.use(router.routes());
  app.use(error(this));
  app.use(invalidRoute);
  app.use(router.allowedMethods({
    throw: true,
    methodNotAllowed: () => new errors.InvalidRequestError('method not allowed', 405),
    notImplemented: () => new errors.InvalidRequestError('not implemented', 501),
  }));
};
