'use strict';

const pkg = require('../package.json');

const events = require('events');
const koa = require('koa');
const _ = require('lodash');
const url = require('url');
const Router = require('koa-router');
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

const getResumeMiddleware = require('./middlewares/resume');
const getSessionMiddleware = require('./middlewares/session');
const error = require('./middlewares/api_error_handler');
const getAuthError = require('./middlewares/authorization_error_handler');

const getConfiguration = require('./helpers/configuration');
const getContext = require('./helpers/oidc_context');
const errors = require('./helpers/errors');

class Provider extends events.EventEmitter {
  constructor(issuer, setup) {
    super();

    this.issuer = issuer;

    const Configuration = getConfiguration(setup);

    Object.defineProperties(this, {
      app: { value: koa() },
      keystore: {
        writable: process.env.NODE_ENV === 'test',
        value: jose.JWK.createKeyStore(),
      },
      configuration: {
        value(path) {
          if (path) return _.get(Configuration, path);
          return Configuration;
        },
      },
      grantTypeHandlers: { value: new Map() },
      grantTypeWhitelist: { value: new Set(['grant_type']) },
    });

    Object.defineProperty(this, 'get', {
      value: _.memoize(function memoizeModels(model) {
        switch (model) {
          case 'Account':
            return { findById: Configuration.findById };
          case 'Client':
            return getClient(this);
          case 'Session':
            return getSession(this);
          case 'IdToken':
            return getIdToken(this);
          case 'OAuthToken':
            return getOauthToken(this);
          case 'AccessToken':
            return getAccessToken(this);
          case 'AuthorizationCode':
            return getAuthorizationCode(this);
          case 'ClientCredentials':
            return getClientCredentials(this);
          case 'RefreshToken':
            return getRefreshToken(this);
          /* istanbul ignore next */
          default:
            throw new Error('unrecognized model');
        }
      }),
    });

    const router = new Router();

    const mountPath = url.parse(this.issuer).pathname;
    const routes = Configuration.routes;

    Configuration.grantTypes.forEach(grantType => {
      try {
        const grant = require(`./actions/token/${grantType}`); // eslint-disable-line global-require
        this.registerGrantType(grantType, grant.handler, grant.parameters);
      } catch (err) {
        /* istanbul ignore if */
        if (err.code !== 'MODULE_NOT_FOUND') {
          throw err;
        }
      }
    });

    function mount(method, name, path) {
      const middlewares = Array.prototype.slice.call(arguments, 3);
      const resolvePath = url.resolve('/', path);
      const argsArray = [name, resolvePath];
      middlewares.forEach((middleware) => argsArray.push(middleware));
      router[method].apply(router, argsArray);
    }

    function get() {
      const args = Array.prototype.slice.call(arguments);
      args.unshift('get');
      mount.apply(null, args);
    }

    function post() {
      const args = Array.prototype.slice.call(arguments);
      args.unshift('post');
      mount.apply(null, args);
    }

    const session = getSessionMiddleware(this);
    const authError = getAuthError(this);

    const authorization = getAuthorization(this);
    get('authorization', routes.authorization, authError, session, authorization);
    post('authorization', routes.authorization, authError, session, authorization);

    const resume = getResumeMiddleware(this);
    get('resume', `${routes.authorization}/:grant`, authError, session, resume, authorization);

    const userinfo = getUserinfo(this);
    get('userinfo', routes.userinfo, userinfo);
    post('userinfo', routes.userinfo, userinfo);

    const token = getToken(this);
    post('token', routes.token, error(this, 'grant.error'), token);

    const certificates = getCertificates(this);
    get('certificates', routes.certificates, error(this, 'certificates.error'), certificates);

    if (Configuration.features.registration) {
      const registration = getRegistration(this);
      post('registration', routes.registration, error(this, 'registration.error'),
        registration.post);

      get('registration_client', `${routes.registration}/:clientId`,
        error(this, 'registration.error'), registration.get);
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
      const discovery = getDiscovery(this);
      get('webfinger', '/.well-known/webfinger', error(this, 'webfinger.error'), webfinger);
      get('discovery', '/.well-known/openid-configuration', error(this, 'discovery.error'),
        discovery);
    }

    if (Configuration.features.sessionManagement) {
      const checkFrame = getCheckSession(this);

      get('check_session', routes.check_session, error(this, 'check_session.error'), checkFrame);

      const endSession = getEndSession(this);

      get('end_session', routes.end_session, error(this, 'end_session.error'), session, endSession);
      post('end_session', routes.end_session, error(this, 'end_session.error'), session,
        endSession);
    }

    Object.defineProperty(this, 'pathFor', {
      writable: true,
      value(name, opts) {
        return [
          mountPath !== '/' ? mountPath : undefined,
          router.url(name, opts),
        ].join('');
      },
    });

    const OIDCContext = getContext(this);

    this.app.use(function * contextEnsureOidc(next) {
      Object.defineProperty(this, 'oidc', {
        value: new OIDCContext(this),
      });
      yield next;
    });

    this.app.use(router.routes());
    this.app.use(error(this));

    this.app.use(function * invalidRoute(next) {
      yield next;
      if (this.status === 404 && this.message === 'Not Found') {
        this.throw(new errors.InvalidRequestError('unrecognized route', 404));
      }
    });

    this.app.use(router.allowedMethods({
      throw: true,
      methodNotAllowed: () => new errors.InvalidRequestError('method not allowed', 405),
      notImplemented: () => new errors.InvalidRequestError('not implemented', 501),
    }));
  }
}

Provider.prototype.urlFor = function urlFor(name, opt) {
  return url.resolve(this.issuer, this.pathFor(name, opt));
};

Provider.prototype.resume = function resume(ctx, grant, result) {
  const resumeUrl = this.urlFor('resume', { grant });

  ctx.cookies.set('_grant_result', JSON.stringify(result), _.merge({
    path: url.parse(resumeUrl).pathname,
  }, this.configuration('cookies.short')));

  ctx.redirect(resumeUrl);
};

Provider.prototype.addClient = function addClient(client) {
  return this.get('Client').add(client);
};

Provider.prototype.userAgent = function userAgent() {
  return `${pkg.name}/${pkg.version} (${this.issuer}; ${pkg.homepage})`;
};

Provider.prototype.registerGrantType = function registerGrantType(name, handlerFactory, params) {
  this.configuration('grantTypes').add(name);
  this.grantTypeHandlers.set(name, handlerFactory(this));

  switch (typeof params) {
    case 'undefined':
      break;
    case 'string':
      if (params) this.grantTypeWhitelist.add(params);
      break;
    default:
      if (params && params.forEach) {
        params.forEach(this.grantTypeWhitelist.add.bind(this.grantTypeWhitelist));
      }
  }
};

Provider.prototype.addKey = function addKey(key) {
  return this.keystore.add(key).then((jwk) => {
    // check if private key was added
    try {
      jwk.toPEM(true);
    } catch (err) {
      this.keystore.remove(jwk);
      throw new Error('only private keys should be added');
    }

    if (this.configuration('features.encryption')) {
      const encryptionAlgs = jwk.algorithms('wrap');
      [
        // 'idTokenEncryptionAlgValues',
        'requestObjectEncryptionAlgValues',
        // 'userinfoEncryptionAlgValues',
      ].forEach((prop) => {
        this.configuration()[prop] = _.union(this.configuration()[prop], encryptionAlgs);
      });
    }

    const signingAlgs = jwk.algorithms('sign');
    [
      'idTokenSigningAlgValues',
      // 'requestObjectSigningAlgValues',
      // 'tokenEndpointAuthSigningAlgValues',
      'userinfoSigningAlgValues',
    ].forEach((prop) => {
      this.configuration()[prop] = _.union(this.configuration()[prop], signingAlgs);
    });

    return Promise.resolve(jwk);
  });
};

module.exports = Provider;
