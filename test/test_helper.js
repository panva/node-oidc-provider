/* eslint-disable no-underscore-dangle */

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const { parse } = require('url');
const path = require('path');
const querystring = require('querystring');
const { createServer } = require('http');

const sinon = require('sinon');
const flatten = require('lodash/flatten');
const { agent: supertest } = require('supertest');
const { expect } = require('chai');
const koaMount = require('koa-mount');
const base64url = require('base64url');
const KeyGrip = require('keygrip'); // eslint-disable-line import/no-extraneous-dependencies
const Connect = require('connect');
const Express = require('express');
const Fastify = require('fastify');
const middie = require('middie');
const Koa = require('koa');

const nanoid = require('../lib/helpers/nanoid');
const epochTime = require('../lib/helpers/epoch_time');
const { Provider } = require('../lib');

const { Account, TestAdapter } = require('./models');

global.i = require('../lib/helpers/weak_cache');

Object.defineProperties(Provider.prototype, {
  enable: {
    value(feature, options = {}) {
      const config = i(this).configuration(`features.${feature}`);
      if (!config) {
        throw new Error(`invalid feature: ${feature}`);
      }

      Object.keys(options).forEach((key) => {
        if (!(key in config)) {
          throw new Error(`invalid option: ${key}`);
        }
      });

      config.enabled = true;
      Object.assign(config, options);

      return this;
    },
  },
});

function readCookie(value) {
  expect(value).to.exist;
  const parsed = querystring.parse(value, '; ');
  const key = Object.keys(parsed)[0];
  return parsed[key];
}

const { port } = global.server.address();

const jwt = (token) => JSON.parse(base64url.decode(token.split('.')[1])).jti;
const paseto = (token) => JSON.parse(base64url.toBuffer(token.split('.')[2]).slice(0, -64)).jti;

module.exports = function testHelper(dir, {
  config: base = path.basename(dir),
  protocol = 'http:',
  mountVia = process.env.MOUNT_VIA,
  mountTo = mountVia ? process.env.MOUNT_TO || '/' : '/',
} = {}) {
  const afterPromises = [];

  after(async () => {
    TestAdapter.clear();
    global.server.removeAllListeners('request');
    await Promise.all(afterPromises.map((x) => x()));
  });

  return async function () {
    const conf = path.format({ dir, base: `${base}.config.js` });
    let { config, client, clients } = require(conf); // eslint-disable-line

    if (client && !clients) {
      clients = [client];
    }

    if (!config.findAccount) {
      config.findAccount = Account.findAccount;
    }

    const issuerIdentifier = `${protocol}//127.0.0.1:${port}`;

    const provider = new Provider(issuerIdentifier, {
      clients,
      jwks: global.keystore.toJWKS(true),
      adapter: TestAdapter,
      ...config,
    });

    let agent;

    function logout() {
      const expire = new Date(0);
      const cookies = [
        `_session=; path=/; expires=${expire.toGMTString()}; httponly`,
        `_session.legacy=; path=/; expires=${expire.toGMTString()}; httponly`,
        `_session.sig=; path=/; expires=${expire.toGMTString()}; httponly`,
        `_session.legacy.sig=; path=/; expires=${expire.toGMTString()}; httponly`,
      ];

      clients.forEach((cl) => {
        cookies.push(`_state.${cl.client_id}=; path=/; expires=${expire.toGMTString()}; httponly`);
        cookies.push(`_state.${cl.client_id}.sig=; path=/; expires=${expire.toGMTString()}; httponly`);
        cookies.push(`_state.${cl.client_id}.legacy=; path=/; expires=${expire.toGMTString()}; httponly`);
        cookies.push(`_state.${cl.client_id}.legacy.sig=; path=/; expires=${expire.toGMTString()}; httponly`);
      });

      return agent._saveCookies.bind(agent)({ headers: { 'set-cookie': cookies } });
    }

    function login({
      scope = 'openid', claims, rejectedScopes = [], rejectedClaims = [],
    } = {}) {
      const sessionId = nanoid();
      const loginTs = epochTime();
      const expire = new Date();
      expire.setDate(expire.getDate() + 1);
      const account = nanoid();
      this.loggedInAccountId = account;

      const keys = new KeyGrip(i(provider).configuration('cookies.keys'));
      const session = new (provider.Session)({ jti: sessionId, loginTs, account });
      const sessionCookie = `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`;
      const cookies = [sessionCookie];

      let [pre, ...post] = sessionCookie.split(';');
      cookies.push([`_session.sig=${keys.sign(pre)}`, ...post].join(';'));

      session.authorizations = {};
      clients.forEach((cl) => {
        const ctx = new provider.OIDCContext({ req: { socket: {} }, res: {} });
        ctx.params = { scope, claims };

        if (ctx.params.claims && typeof ctx.params.claims !== 'string') {
          ctx.params.claims = JSON.stringify(ctx.params.claims);
        }

        session.authorizations[cl.client_id] = {
          sid: nanoid(),
          grantId: nanoid(),
          promptedScopes: scope.split(' '),
          promptedClaims: [...ctx.requestParamClaims],
          rejectedScopes,
          rejectedClaims,
        };

        if (i(provider).configuration('features.sessionManagement.enabled')) {
          const cookie = `_state.${cl.client_id}=${session.stateFor(cl.client_id)}; path=/; expires=${expire.toGMTString()}`;
          cookies.push(cookie);
          [pre, ...post] = cookie.split(';');
          cookies.push([`_state.${cl.client_id}.sig=${keys.sign(pre)}`, ...post].join(';'));
        }
      });

      return Account.findAccount({}, account).then(session.save()).then(() => {
        agent._saveCookies.bind(agent)({ headers: { 'set-cookie': cookies } });
      });
    }

    class AuthorizationRequest {
      constructor(parameters = {}) {
        if (parameters.claims && typeof parameters.claims !== 'string') {
          parameters.claims = JSON.stringify(parameters.claims); // eslint-disable-line no-param-reassign, max-len
        }

        Object.assign(this, parameters);

        this.client_id = 'client_id' in parameters ? parameters.client_id : clients[0].client_id;
        const c = clients.find((cl) => cl.client_id === this.client_id);
        this.state = 'state' in parameters ? parameters.state : Math.random().toString();
        this.redirect_uri = 'redirect_uri' in parameters ? parameters.redirect_uri : parameters.redirect_uri || (c && c.redirect_uris[0]);
        this.res = {};

        if (this.response_type && this.response_type.includes('id_token')) {
          this.nonce = 'nonce' in parameters ? parameters.nonce : Math.random().toString();
        }

        Object.defineProperty(this, 'validateClientLocation', {
          value: (response) => {
            const expected = parse(this.redirect_uri, true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
          },
        });

        Object.defineProperty(this, 'validateState', {
          value: (response) => {
            const { query: { state } } = parse(response.headers.location, true);
            expect(state).to.equal(this.state);
          },
        });

        Object.defineProperty(this, 'validateInteractionRedirect', {
          value: (response) => {
            const { hostname, search, query } = parse(response.headers.location);
            expect(hostname).to.be.null;
            expect(search).to.be.null;
            expect(query).to.be.null;
            expect(response).to.have.nested.property('headers.set-cookie').that.is.an('array');

            const grantid = readCookie(response.headers['set-cookie'][0]);
            expect(readCookie(response.headers['set-cookie'][0])).to.equal(readCookie(response.headers['set-cookie'][2]));

            const interaction = TestAdapter.for('Interaction').syncFind(grantid);

            Object.entries(this).forEach(([key, value]) => {
              if (key === 'res') return;
              if (key === 'request') return;
              if (key === 'request_uri') return;
              if (key === 'max_age' && value === 0) {
                expect(interaction.params).not.to.have.property('max_age');
                expect(interaction.params).to.have.property('prompt').that.contains('login');
              } else {
                expect(interaction.params).to.have.property(key, value);
              }
            });
          },
        });
      }
    }

    AuthorizationRequest.prototype.validateInteraction = (eName, ...eReasons) => { // eslint-disable-line arrow-body-style, max-len
      return (response) => {
        const grantid = readCookie(response.headers['set-cookie'][0]);
        const { prompt: { name, reasons } } = TestAdapter.for('Interaction').syncFind(grantid);
        expect(name).to.equal(eName);
        expect(reasons).to.contain.members(eReasons);
      };
    };

    AuthorizationRequest.prototype.validateFragment = function (response) {
      const { hash } = parse(response.headers.location);
      expect(hash).to.exist;
      response.headers.location = response.headers.location.replace('#', '?'); // eslint-disable-line no-param-reassign
    };

    AuthorizationRequest.prototype.validatePresence = function (keys, all) {
      let absolute;
      if (all === undefined) {
        absolute = true;
      } else {
        absolute = all;
      }

      return (response) => {
        const { query } = parse(response.headers.location, true);
        if (absolute) {
          expect(query).to.have.keys(keys);
        } else {
          expect(query).to.contain.keys(keys);
        }
        keys.forEach((key) => {
          this.res[key] = query[key];
        });
      };
    };

    AuthorizationRequest.prototype.validateResponseParameter = function (parameter, expected) {
      return (response) => {
        const { query: { [parameter]: value } } = parse(response.headers.location, true);
        if (expected.exec) {
          expect(value).to.match(expected);
        } else {
          expect(value).to.equal(expected);
        }
      };
    };

    AuthorizationRequest.prototype.validateError = function (expected) {
      return this.validateResponseParameter('error', expected);
    };

    AuthorizationRequest.prototype.validateScope = function (expected) {
      return this.validateResponseParameter('scope', expected);
    };

    AuthorizationRequest.prototype.validateErrorDescription = function (expected) {
      return this.validateResponseParameter('error_description', expected);
    };

    function getSession({ instantiate } = { instantiate: false }) {
      const { value: sessionId } = agent.jar.getCookie('_session', { path: '/' });
      const raw = TestAdapter.for('Session').syncFind(sessionId);

      if (instantiate) {
        return new provider.Session(raw);
      }

      return raw;
    }

    function getSessionId() {
      const { value: sessionId } = agent.jar.getCookie('_session', { path: '/' }) || {};
      return sessionId;
    }

    function wrap(opts) {
      const {
        route, verb, auth, params,
      } = opts;
      switch (verb) {
        case 'get':
          return agent
            .get(route)
            .query(auth || params);
        case 'post':
          return agent
            .post(route)
            .send(auth || params)
            .type('form');
        default:
          throw new Error('invalid wrap verb');
      }
    }

    function assertOnce(fn, done, finished) {
      let final;
      let finish;
      return async (ctx, next) => {
        await next();
        if (typeof finished === 'function') {
          finish = finished(ctx);
        } else if (!finish) {
          finish = true;
        }
        if (!final && finish) {
          final = true;
          try {
            await fn(ctx);
            done();
          } catch (err) {
            done(err);
          }
        }
      };
    }

    function getTokenJti(token) {
      try {
        return jwt(token);
      } catch (err) {}

      try {
        return paseto(token);
      } catch (err) {}

      return token; // opaque
    }

    function failWith(code, error, error_description, scope) {
      return ({ status, body, headers: { 'www-authenticate': wwwAuth } }) => {
        const { provider: { issuer } } = this;
        expect(status).to.eql(code);
        expect(body).to.have.property('error', error);
        expect(body).to.have.property('error_description', error_description);
        expect(wwwAuth).to.match(new RegExp(`^Bearer realm="${issuer}"`));
        let assert = expect(wwwAuth);
        if (error_description === 'no access token provided') {
          assert = assert.not.to;
        } else {
          assert = assert.to;
        }
        assert.match(new RegExp(`error="${error}"`));
        assert.match(new RegExp(`error_description="${error_description.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}"`));
        if (scope) assert.match(new RegExp(`scope="${scope}"`));
      };
    }

    Object.assign(this, {
      assertOnce,
      AuthorizationRequest,
      failWith,
      getSession,
      getSessionId,
      getTokenJti,
      login,
      logout,
      provider,
      TestAdapter,
      wrap,
    });

    switch (mountVia) {
      case 'koa': {
        const app = new Koa();
        app.use(koaMount(mountTo, provider.app));
        global.server.on('request', app.callback());
        this.app = app;
        break;
      }
      case 'express': {
        const app = new Express();
        app.use(mountTo, provider.callback);
        global.server.on('request', app);
        break;
      }
      case 'connect': {
        const app = new Connect();
        app.use(mountTo, provider.callback);
        global.server.on('request', app);
        break;
      }
      case 'fastify': {
        const app = new Fastify();
        await app.register(middie);
        app.use(mountTo, provider.callback);
        await new Promise((resolve) => global.server.close(resolve));
        await app.listen(port);
        global.server = app.server;
        afterPromises.push(async () => {
          await app.close();
          global.server = createServer().listen(port);
          await new Promise((resolve) => global.server.once('listening', resolve));
        });
        break;
      }
      case 'hapi': {
        const Hapi = require('@hapi/hapi'); // eslint-disable-line global-require
        const app = new Hapi.Server({ port });
        const { callback } = provider;
        app.route({
          path: `${mountTo}/{any*}`,
          method: '*',
          config: { payload: { output: 'stream', parse: false } },
          async handler({ raw: { req, res } }, h) {
            req.originalUrl = req.url;
            req.url = req.url.replace(mountTo, '');

            await new Promise((resolve) => {
              res.on('finish', resolve);
              callback(req, res);
            });

            req.url = req.url.replace('/', mountTo);
            delete req.originalUrl;

            return res.finished ? h.abandon : h.continue;
          },
        });
        await new Promise((resolve) => global.server.close(resolve));
        await app.start();
        global.server = app.listener;
        afterPromises.push(async () => {
          await app.stop();
          global.server = createServer().listen(port);
          await new Promise((resolve) => global.server.once('listening', resolve));
        });
        break;
      }
      default:
        global.server.on('request', provider.callback);
    }

    agent = supertest(global.server);

    if (mountTo !== '/') {
      ['get', 'post', 'put', 'del', 'options', 'trace'].forEach((method) => {
        const orig = agent[method];
        agent[method] = function (route, ...args) {
          if (route.startsWith(`${mountTo}/`)) {
            return orig.call(this, route, ...args);
          }
          return orig.call(this, `${mountTo}${route}`, ...args);
        };
      });
    }

    this.suitePath = (unprefixed) => {
      if (mountTo === '/') {
        return unprefixed;
      }

      return `${mountTo}${unprefixed}`;
    };

    this.agent = agent;
  };
};

module.exports.passInteractionChecks = (...reasons) => {
  const cb = reasons.pop();

  const sandbox = sinon.createSandbox();

  context('', () => {
    before(function () {
      const { policy } = i(this.provider).configuration('interactions');

      const iChecks = flatten(policy.map((i) => i.checks));

      iChecks
        .filter((check) => reasons.includes(check.reason))
        .forEach((check) => {
          sandbox.stub(check, 'check').returns(false);
        });
    });

    after(sandbox.restore);

    cb();
  });
};

module.exports.skipConsent = () => {
  const sandbox = sinon.createSandbox();

  before(function () {
    sandbox.stub(this.provider.OIDCContext.prototype, 'promptPending').returns(false);
    sandbox.stub(this.provider.OIDCContext.prototype, 'requestParamScopes').get(() => new Set());
    sandbox.stub(this.provider.OIDCContext.prototype, 'requestParamClaims').get(() => new Set());
    sandbox.stub(this.provider.OIDCContext.prototype, 'acceptedScope').callsFake(function () {
      return this.params.scope;
    });
  });

  after(sandbox.restore);
};
