'use strict';

const pkg = require('../package.json');
const deprecations = require('./deprecations');

const events = require('events');
const koa = require('koa');
const _ = require('lodash');
const url = require('url');
const Router = require('koa-router');
const getCors = require('kcors');
const jose = require('node-jose');

const getClient = require('./models/client');
const getIdToken = require('./models/id_token');
const getOauthToken = require('./models/oauth_token');
const getSession = require('./models/session');
const getAccessToken = require('./models/access_token');
const getAuthorizationCode = require('./models/authorization_code');
const getClientCredentials = require('./models/client_credentials');
const getRefreshToken = require('./models/refresh_token');

const getAuthorization = require('./actions/authorization');
const getUserinfo = require('./actions/userinfo');
const getToken = require('./actions/token');
const getCertificates = require('./actions/certificates');
const getRegistration = require('./actions/registration');
const getRevocation = require('./actions/revocation');
const getIntrospection = require('./actions/introspection');
const getWebfinger = require('./actions/webfinger');
const getDiscovery = require('./actions/discovery');
const getCheckSession = require('./actions/check_session');
const getEndSession = require('./actions/end_session');

const getResumeMiddleware = require('./shared/resume');
const getSessionMiddleware = require('./shared/session');
const error = require('./shared/error_handler');
const getAuthError = require('./shared/authorization_error_handler');
const invalidRoute = require('./shared/invalid_route');
const contextEnsureOidc = require('./shared/context_ensure_oidc');

const getConfiguration = require('./helpers/configuration');
const errors = require('./helpers/errors');
const instance = require('./helpers/weak_cache');

const DEFAULT_HTTP_OPTIONS = require('./consts/default_http_options');

class Provider extends events.EventEmitter {
  constructor(issuer, setup) {
    super();

    this.issuer = issuer;
    const Configuration = getConfiguration(setup);

    instance(this).defaultHttpOptions = _.clone(DEFAULT_HTTP_OPTIONS);
    instance(this).responseModes = new Map();
    instance(this).grantTypeHandlers = new Map();
    instance(this).grantTypeWhitelist = new Set(['grant_type']);
    instance(this).mountPath = url.parse(this.issuer).pathname;

    const app = koa();
    instance(this).app = app;

    /* istanbul ignore if */
    if (Configuration.keystore) {
      Object.defineProperty(this, 'addKey', {
        value: () => { throw new Error('addKey is incompatible with config.keystore'); },
      });
    }

    Object.defineProperties(this, {
      keystore: {
        writable: process.env.NODE_ENV === 'test',
        value: Configuration.keystore || jose.JWK.createKeyStore(),
      },
      configuration: {
        value(path) {
          if (path) return _.get(Configuration, path);
          return Configuration;
        },
      },
    });

    instance(this).OAuthToken = getOauthToken(this);
    instance(this).Account = { findById: Configuration.findById };
    instance(this).IdToken = getIdToken(this);
    instance(this).Client = getClient(this);
    instance(this).Session = getSession(this);
    instance(this).AccessToken = getAccessToken(this);
    instance(this).AuthorizationCode = getAuthorizationCode(this);
    instance(this).RefreshToken = getRefreshToken(this);
    instance(this).ClientCredentials = getClientCredentials(this);

    const router = new Router();
    instance(this).router = router;

    const get = router.get.bind(router);
    const post = router.post.bind(router);
    const del = router.del.bind(router);
    const put = router.put.bind(router);
    const options = router.options.bind(router);

    const routes = Configuration.routes;
    const onlyGetCors = getCors({ allowedMethods: 'GET' });

    Configuration.grantTypes.forEach((grantType) => {
      try {
        const grant = require(`./actions/token/${grantType}`); // eslint-disable-line global-require
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

    if (Configuration.features.registration) {
      const registration = getRegistration(this);
      const clientRoute = `${routes.registration}/:clientId`;

      post('registration', routes.registration, error(this, 'registration_create.error'),
        registration.post);
      get('registration_client', clientRoute, error(this, 'registration_read.error'),
        registration.get);

      if (Configuration.features.registrationManagement) {
        put(clientRoute, error(this, 'registration_update.error'), registration.put);
        del(clientRoute, error(this, 'registration_delete.error'), registration.delete);
      }
    }

    if (Configuration.features.revocation) {
      const revocation = getRevocation(this);
      post('revocation', routes.revocation, error(this, 'revocation.error'), revocation);
    }

    if (Configuration.features.introspection) {
      const introspection = getIntrospection(this);
      post('introspection', routes.introspection, error(this, 'introspection.error'),
        introspection);
    }

    if (Configuration.features.discovery) {
      const webfinger = getWebfinger(this);
      const webfingerRoute = '/.well-known/webfinger';
      get('webfinger', webfingerRoute, onlyGetCors, error(this, 'webfinger.error'), webfinger);
      options(webfingerRoute, onlyGetCors);

      const discovery = getDiscovery(this);
      const discoveryRoute = '/.well-known/openid-configuration';
      get('discovery', discoveryRoute, onlyGetCors, error(this, 'discovery.error'), discovery);
      options(discoveryRoute, onlyGetCors);
    }

    if (Configuration.features.sessionManagement) {
      const checkFrame = getCheckSession(this);
      get('check_session', routes.check_session, error(this, 'check_session.error'), checkFrame);

      const endSession = getEndSession(this);
      get('end_session', routes.end_session, error(this, 'end_session.error'), session,
        endSession.get);
      post(routes.end_session, error(this, 'end_session.error'), session, endSession.post);
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
  }

  urlFor(name, opt) {
    return url.resolve(this.issuer, this.pathFor(name, opt));
  }

  registerGrantType(name, handlerFactory, params) {
    this.configuration('grantTypes').add(name);

    const grantTypeHandlers = instance(this).grantTypeHandlers;
    const grantTypeWhitelist = instance(this).grantTypeWhitelist;

    grantTypeHandlers.set(name, handlerFactory(this));

    switch (typeof params) {
      case 'undefined':
        break;
      case 'string':
        if (params) grantTypeWhitelist.add(params);
        break;
      default:
        if (params && params.forEach) {
          params.forEach(grantTypeWhitelist.add.bind(grantTypeWhitelist));
        }
    }
  }

  registerResponseMode(name, handler) { instance(this).responseModes.set(name, handler); }

  get app() { return instance(this).app; }

  pathFor(name, opts) {
    const mountPath = instance(this).mountPath;
    const router = instance(this).router;
    return [mountPath !== '/' ? mountPath : undefined, router.url(name, opts)].join('');
  }

  resume(ctx, grant, result) {
    const resumeUrl = this.urlFor('resume', { grant });
    const path = url.parse(resumeUrl).pathname;
    const opts = _.merge({ path }, this.configuration('cookies.short'));

    ctx.cookies.set('_grant_result', JSON.stringify(result), opts);
    ctx.redirect(resumeUrl);
  }

  addClient(client, dynamic) {
    if (this.configuration('features.registrationManagement') && !dynamic) {
      return this.Client.add(client, dynamic).then((addedClient) => {
        Object.defineProperty(addedClient, 'noManage', { value: true });
        return addedClient;
      });
    }
    return this.Client.add(client, dynamic);
  }

  httpOptions(values) {
    return _.merge({
      headers: {
        'User-Agent': `${pkg.name}/${pkg.version} (${this.issuer}; ${pkg.homepage})`,
      },
    }, this.defaultHttpOptions, values);
  }

  get defaultHttpOptions() { return instance(this).defaultHttpOptions; }

  set defaultHttpOptions(value) {
    instance(this).defaultHttpOptions = _.merge({}, DEFAULT_HTTP_OPTIONS, value);
  }

  get OAuthToken() { return instance(this).OAuthToken; }
  get Account() { return instance(this).Account; }
  get IdToken() { return instance(this).IdToken; }
  get Client() { return instance(this).Client; }
  get Session() { return instance(this).Session; }
  get AccessToken() { return instance(this).AccessToken; }
  get AuthorizationCode() { return instance(this).AuthorizationCode; }
  get RefreshToken() { return instance(this).RefreshToken; }
  get ClientCredentials() { return instance(this).ClientCredentials; }
  get RegistrationAccessToken() { return instance(this).RegistrationAccessToken; }
  get InitialAccessToken() { return instance(this).InitialAccessToken; }
}

deprecations(Provider);

module.exports = Provider;
