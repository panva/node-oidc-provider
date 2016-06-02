'use strict';

const koa = require('koa');
const pkg = require('../package.json');
const events = require('events');
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

const getAuthentication = require('./actions/authentication');
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

const getRespondMiddleware = require('./middlewares/respond');
const getSessionMiddleware = require('./middlewares/session');
const apiErrorHandlerMiddleware = require('./middlewares/api_error_handler');

const getConfiguration = require('./helpers/configuration');

class Provider extends events.EventEmitter {
  constructor(issuer, setup) {
    super();

    this.issuer = issuer;

    Object.defineProperty(this, 'configuration', {
      value: getConfiguration(setup),
    });

    Object.defineProperties(this, {
      Client: {
        value: getClient(this),
      },
      IdToken: {
        value: getIdToken(this),
      },
      OAuthToken: {
        value: getOauthToken(this),
      },
      Session: {
        value: getSession(this),
      },
      app: {
        value: koa(),
      },
      keystore: {
        writable: process.env.NODE_ENV === 'test',
        value: jose.JWK.createKeyStore(),
      },
      router: {
        value: new Router(),
      },
    });

    this.mountPath = url.parse(this.issuer).pathname;

    Object.defineProperties(this, {
      AccessToken: {
        value: getAccessToken(this.OAuthToken),
      },
      AuthorizationCode: {
        value: getAuthorizationCode(this.OAuthToken),
      },
      ClientCredentials: {
        value: getClientCredentials(this.OAuthToken),
      },
      RefreshToken: {
        value: getRefreshToken(this.OAuthToken),
      },
    });

    this.AccessToken.expiresIn = this.configuration.ttl.accessToken;
    this.AuthorizationCode.expiresIn = this.configuration.ttl.authorizationCode;
    this.ClientCredentials.expiresIn = this.configuration.ttl.clientCredentials;
    this.IdToken.expiresIn = this.configuration.ttl.idToken;
    this.RefreshToken.expiresIn = this.configuration.ttl.refreshToken;

    const session = getSessionMiddleware(this);
    const errorHandler = apiErrorHandlerMiddleware;

    const authentication = getAuthentication(this);
    const authMountPath = url.resolve('/',
      this.configuration.routes.authentication);
    this.router.get('authentication',
      authMountPath, session, authentication);
    this.router.post('authentication',
      authMountPath, session, authentication);

    const respond = getRespondMiddleware(this);
    const respondMountPath = url.resolve('/', `${authMountPath}/:grant`);
    this.router.get('respond',
      respondMountPath, session, respond, authentication);

    const userinfo = getUserinfo(this);
    const userinfoMountPath = url.resolve('/',
      this.configuration.routes.userinfo);
    this.router.get('userinfo',
      userinfoMountPath, userinfo);
    this.router.post('userinfo',
      userinfoMountPath, userinfo);

    const token = getToken(this);
    const tokenMountPath = url.resolve('/', this.configuration.routes.token);
    this.router.post('token',
      tokenMountPath, errorHandler(this, 'grant.error'), token);

    const certificates = getCertificates(this);
    const certMountPath = url.resolve('/',
      this.configuration.routes.certificates);
    this.router.get('certificates',
      certMountPath, errorHandler(this, 'certificates.error'), certificates);

    if (this.configuration.features.registration) {
      const registration = getRegistration(this);

      const regMountPath = url.resolve('/',
        this.configuration.routes.registration);
      const regClientMountPath = `${regMountPath}/:clientId`;
      this.router.post('registration',
        regMountPath, errorHandler(this,
          'registration.error'), registration.post);
      this.router.get('registration_client',
        regClientMountPath, errorHandler(this,
          'registration.error'), registration.get);
    }

    if (this.configuration.features.revocation) {
      const revocation = getRevocation(this);
      const revokeMountPath = url.resolve('/',
        this.configuration.routes.revocation);

      this.router.post('revocation',
        revokeMountPath, errorHandler(this, 'revocation.error'), revocation);
    }

    if (this.configuration.features.introspection) {
      const introspection = getIntrospection(this);
      const introMountPath = url.resolve('/',
        this.configuration.routes.introspection);

      this.router.post('introspection',
        introMountPath, errorHandler(this,
          'introspection.error'), introspection);
    }

    if (this.configuration.features.discovery) {
      const webfinger = getWebfinger(this);
      const discovery = getDiscovery(this);
      this.router.get('webfinger',
        '/.well-known/webfinger', errorHandler(this,
          'webfinger.error'), webfinger);
      this.router.get('discovery',
        '/.well-known/openid-configuration', errorHandler(this,
          'discovery.error'), discovery);
    }

    if (this.configuration.features.sessionManagement) {
      const checkFrame = getCheckSession(this);
      const checkFrameMountPath = url.resolve('/',
        this.configuration.routes.check_session);

      this.router.get('check_session',
        checkFrameMountPath, errorHandler(this,
          'check_session.error'), checkFrame);

      const endSession = getEndSession(this);
      const endSessionMountPath = url.resolve('/',
        this.configuration.routes.end_session);

      this.router.get('end_session',
        endSessionMountPath, errorHandler(this,
          'end_session.error'), session, endSession);
    }

    const self = this;

    this.app.use(function * contextEnsureOidc(next) {
      this.oidc = {};

      this.oidc.pathFor = (name, opt) => self.pathFor(name, opt);
      this.oidc.urlFor = (name, opt) => url.resolve(this.href, this.oidc.pathFor(name, opt));

      yield next;
    });

    this.app.use(this.router.routes());
    this.app.use(this.router.allowedMethods());
  }
}

Provider.prototype.pathFor = function pathFor(name, opts) {
  return [
    this.mountPath !== '/' ? this.mountPath : undefined,
    this.router.url(name, opts),
  ].join('');
};

Provider.prototype.respond = function respond(ctx, grant, result) {
  const respondPath = this.pathFor('respond', {
    grant,
  });

  ctx.cookies.set('_grant_result', JSON.stringify(result), _.merge({
    path: respondPath,
  }, this.configuration.cookies.short));
  ctx.redirect(respondPath);
};

Provider.prototype.addClient = function addClient(client) {
  return this.Client.add(client);
};

Provider.prototype.userAgent = function userAgent() {
  return `${pkg.name}/${pkg.version} (${this.issuer}; ${pkg.homepage})`;
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

    if (this.configuration.features.encryption) {
      const encryptionAlgs = jwk.algorithms('wrap');
      [
        // 'idTokenEncryptionAlgValues',
        'requestObjectEncryptionAlgValues',
        // 'userinfoEncryptionAlgValues',
      ].forEach((prop) => {
        this.configuration[prop] = _.union(this.configuration[prop],
          encryptionAlgs);
      });
    }

    const signingAlgs = jwk.algorithms('sign');
    [
      'idTokenSigningAlgValues',
      // 'requestObjectSigningAlgValues',
      // 'tokenEndpointAuthSigningAlgValues',
      'userinfoSigningAlgValues',
    ].forEach((prop) => {
      this.configuration[prop] = _.union(this.configuration[prop], signingAlgs);
    });

    return Promise.resolve(jwk);
  });
};

module.exports.Provider = Provider;
