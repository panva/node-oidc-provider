'use strict';

let koa = require('koa');
let events = require('events');
let _ = require('lodash');
let url = require('url');
let Router = require('koa-router');
let jose = require('node-jose');

// TODO: CORS config

let getConfiguration = require('./helpers/configuration');

class Provider extends events.EventEmitter {
  constructor(issuer, opts) {
    super();

    this.issuer = issuer;

    opts = opts || {};

    let setup = opts.config;

    Object.defineProperty(this, 'configuration', {
      value: getConfiguration(setup),
    });

    Object.defineProperties(this, {
      Client: {
        value: require('./models/client')(this),
      },
      IdToken: {
        value: require('./models/id_token')(this),
      },
      OAuthToken: {
        value: require('./models/oauth_token')(this),
      },
      Session: {
        value: require('./models/session')(this),
      },
      app: {
        value: koa(),
      },
      keystore: {
        value: jose.JWK.createKeyStore(),
      },
      router: {
        value: new Router(),
      },
    });

    this.mountPath = url.parse(this.issuer).pathname;

    Object.defineProperties(this, {
      AccessToken: {
        value: require('./models/access_token')(this.OAuthToken),
      },
      AuthorizationCode: {
        value: require('./models/authorization_code')(this.OAuthToken),
      },
      ClientCredentials: {
        value: require('./models/client_credentials')(this.OAuthToken),
      },
      RefreshToken: {
        value: require('./models/refresh_token')(this.OAuthToken),
      },
    });

    this.AccessToken.expiresIn = this.configuration.ttl.accessToken;
    this.AuthorizationCode.expiresIn = this.configuration.ttl.authorizationCode;
    this.ClientCredentials.expiresIn = this.configuration.ttl.clientCredentials;
    this.IdToken.expiresIn = this.configuration.ttl.idToken;
    this.RefreshToken.expiresIn = this.configuration.ttl.refreshToken;

    let session = require('./middlewares/session')(this);
    let errorHandler = require('./middlewares/api_error_handler');

    let authentication = require('./actions/authentication')(this);
    let authMountPath = url.resolve('/',
      this.configuration.routes.authentication);
    this.router.get('authentication',
      authMountPath, session, authentication);
    this.router.post('authentication',
      authMountPath, session, authentication);

    let respond = require('./middlewares/respond')(this);
    let respondMountPath = url.resolve('/', authMountPath + '/:grant');
    this.router.get('respond',
      respondMountPath, session, respond, authentication);

    let userinfo = require('./actions/userinfo')(this);
    let userinfoMountPath = url.resolve('/',
      this.configuration.routes.userinfo);
    this.router.get('userinfo',
      userinfoMountPath, userinfo);
    this.router.post('userinfo',
      userinfoMountPath, userinfo);

    let token = require('./actions/token')(this);
    let tokenMountPath = url.resolve('/', this.configuration.routes.token);
    this.router.post('token',
      tokenMountPath, errorHandler(this, 'grant.error'), token);

    let certificates = require('./actions/certificates')(this);
    let certMountPath = url.resolve('/',
      this.configuration.routes.certificates);
    this.router.get('certificates',
      certMountPath, errorHandler(this, 'certificates.error'), certificates);

    if (this.configuration.features.registration) {
      let registration = require('./actions/registration')(this);

      let regMountPath = url.resolve('/',
        this.configuration.routes.registration);
      let regClientMountPath = regMountPath + '/:clientId';
      this.router.post('registration',
        regMountPath, errorHandler(this,
          'registration.error'), registration.post);
      this.router.get('registration_client',
        regClientMountPath, errorHandler(this,
          'registration.error'), registration.get);
    }

    if (this.configuration.features.revocation) {
      let revocation = require('./actions/revocation')(this);
      let revokeMountPath = url.resolve('/',
        this.configuration.routes.revocation);

      this.router.post('revocation',
        revokeMountPath, errorHandler(this, 'revocation.error'), revocation);
    }

    if (this.configuration.features.introspection) {
      let introspection = require('./actions/introspection')(this);
      let introMountPath = url.resolve('/',
        this.configuration.routes.introspection);

      this.router.post('introspection',
        introMountPath, errorHandler(this,
          'introspection.error'), introspection);
    }

    if (this.configuration.features.discovery) {
      let webfinger = require('./actions/webfinger')(this);
      let discovery = require('./actions/discovery')(this);
      this.router.get('webfinger',
        '/.well-known/webfinger', errorHandler(this,
          'webfinger.error'), webfinger);
      this.router.get('discovery',
        '/.well-known/openid-configuration', errorHandler(this,
          'discovery.error'), discovery);
    }

    if (this.configuration.features.sessionManagement) {
      let checkFrame = require('./actions/check_session')(this);
      let checkFrameMountPath = url.resolve('/',
        this.configuration.routes.check_session);

      this.router.get('check_session',
        checkFrameMountPath, errorHandler(this,
          'check_session.error'), checkFrame);

      let endSession = require('./actions/end_session')(this);
      let endSessionMountPath = url.resolve('/',
        this.configuration.routes.end_session);

      this.router.get('end_session',
        endSessionMountPath, errorHandler(this,
          'end_session.error'), session, endSession);
    }

    let _this = this;

    this.app.use(function * (next) {
      this.oidc = {};

      this.oidc.pathFor = (name, opts) => {
        return _this.pathFor(name, opts);
      };

      this.oidc.urlFor = (name, opts) => {
        return url.resolve(this.href, this.oidc.pathFor(name, opts));
      };

      yield next;
    });

    this.app.use(this.router.routes());
    this.app.use(this.router.allowedMethods());
  }
}

Provider.prototype.pathFor = function(name, opts) {
  return [
    this.mountPath !== '/' ? this.mountPath : undefined,
    this.router.url(name, opts)
  ].join('');
};

Provider.prototype.respond = function(ctx, grant, result) {
  let respondPath = this.pathFor('respond', {
    grant: grant,
  });

  ctx.cookies.set('_grant_result', JSON.stringify(result), _.merge({
    path: respondPath,
  }, this.configuration.cookies.short));
  ctx.redirect(respondPath);
};

Provider.prototype.addKey = function(key) {
  return this.keystore.add(key).then((jwk) => {

    if (this.configuration.features.encryption) {
      let encryptionAlgs = jwk.algorithms('wrap');
      [
        // 'idTokenEncryptionAlgValuesSupported',
        'requestObjectEncryptionAlgValuesSupported',
        // 'userinfoEncryptionAlgValuesSupported',
      ].forEach((prop) => {
        this.configuration[prop] = _.union(this.configuration[prop],
          encryptionAlgs);
      });
    }

    let signingAlgs = jwk.algorithms('sign');
    [
      'idTokenSigningAlgValuesSupported',
      // 'requestObjectSigningAlgValuesSupported',
      // 'tokenEndpointAuthSigningAlgValuesSupported',
      'userinfoSigningAlgValuesSupported',
    ].forEach((prop) => {
      this.configuration[prop] = _.union(this.configuration[prop], signingAlgs);
    });

    return Promise.resolve();
  });
};

module.exports.Provider = Provider;
