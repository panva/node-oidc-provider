/* eslint-disable no-underscore-dangle */

import { parse, pathToFileURL } from 'node:url';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import * as querystring from 'node:querystring';
import { createServer } from 'node:http';
import { once } from 'node:events';

import { setGlobalDispatcher, MockAgent } from 'undici';
import sinon from 'sinon';
import { dirname } from 'desm';
import flatten from 'lodash/flatten.js';
import { Request } from 'superagent'; // eslint-disable-line import/no-extraneous-dependencies
import { agent as supertest } from 'supertest';
import { expect } from 'chai';
import koaMount from 'koa-mount';
import base64url from 'base64url';
import { CookieAccessInfo } from 'cookiejar'; // eslint-disable-line import/no-extraneous-dependencies
import Express from 'express';
import Koa from 'koa';

import nanoid from '../lib/helpers/nanoid.js';
import epochTime from '../lib/helpers/epoch_time.js';
import Provider from '../lib/index.js';
import instance from '../lib/helpers/weak_cache.js';

import { Account, TestAdapter } from './models.js';
import keys from './keys.js';

const fetchAgent = new MockAgent();
fetchAgent.disableNetConnect();
setGlobalDispatcher(fetchAgent);

const { _auth } = Request.prototype;

function encodeToken(token) {
  return encodeURIComponent(token).replace(/(?:[-_.!~*'()]|%20)/g, (substring) => {
    switch (substring) {
      case '-':
        return '%2D';
      case '_':
        return '%5F';
      case '.':
        return '%2E';
      case '!':
        return '%21';
      case '~':
        return '%7E';
      case '*':
        return '%2A';
      case "'":
        return '%27';
      case '(':
        return '%28';
      case ')':
        return '%29';
      case '%20':
        return '+';
      default:
        throw new Error();
    }
  });
}

Request.prototype._auth = function (user, pass, options, encoder) {
  if (options?.type === 'basic') {
    return _auth.call(this, encodeToken(user), encodeToken(pass), options, encoder);
  }

  return _auth.call(this, user, pass, options, encoder);
};

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

globalThis.i = instance;

Object.defineProperties(Provider.prototype, {
  enable: {
    value(feature, options = {}) {
      const config = i(this).features[feature];
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

function getSetCookies(response) {
  return response.headers['set-cookie'].filter((val) => !val.includes('Thu, 01 Jan 1970 00:00:00 GMT'));
}

function readCookie(value) {
  expect(value).to.exist;
  const parsed = querystring.parse(value, '; ');
  const key = Object.keys(parsed)[0];
  return parsed[key];
}

const { port } = globalThis.server.address();

const jwt = (token) => JSON.parse(base64url.decode(token.split('.')[1])).jti;

export default function testHelper(importMetaUrl, {
  config: base,
  protocol = 'http:',
  mountVia = process.env.MOUNT_VIA,
  mountTo = mountVia ? process.env.MOUNT_TO || '/' : '/',
} = {}) {
  const dir = dirname(importMetaUrl);
  // eslint-disable-next-line no-param-reassign
  base ??= path.basename(dir);
  const afterPromises = [];

  after(async () => {
    TestAdapter.clear();
    globalThis.server.removeAllListeners('request');
    await Promise.all(afterPromises.map((x) => x()));
  });

  return async function () {
    const conf = pathToFileURL(path.format({ dir, base: `${base}.config.js` })).toString();
    const { default: mod } = await import(conf);
    const { config, client } = mod;
    let { clients } = mod;

    if (client && !clients) {
      clients = [client];
    }

    if (!config.findAccount) {
      config.findAccount = Account.findAccount;
    }

    const issuerIdentifier = `${protocol}//127.0.0.1:${port}`;

    const provider = new Provider(issuerIdentifier, {
      clients,
      jwks: { keys },
      adapter: TestAdapter,
      ...config,
    });

    // eslint-disable-next-line prefer-arrow-callback
    provider.middleware.push(async function neverInvoked(ctx) {
      ctx.throw(500, 'this is never invoked');
    });

    let agent;
    let lastSession;

    function logout() {
      const expire = new Date(0);
      const cookies = [
        `_session=; path=/; expires=${expire.toGMTString()}; httponly`,
      ];

      return agent._saveCookies.bind(agent)({
        request: { url: provider.issuer },
        headers: { 'set-cookie': cookies },
      });
    }

    async function login({
      scope = 'openid',
      claims,
      resources = {},
      rejectedScopes = [],
      rejectedClaims = [],
      accountId = nanoid(),
    } = {}) {
      const sessionId = nanoid();
      const loginTs = epochTime();
      const expire = new Date();
      expire.setDate(expire.getDate() + 1);
      this.loggedInAccountId = accountId;

      const session = new (provider.Session)({ jti: sessionId, loginTs, accountId });
      lastSession = session;
      const sessionCookie = `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`;
      const cookies = [sessionCookie];

      session.authorizations = {};
      const ctx = new provider.OIDCContext({ req: { socket: {} }, res: {} });
      ctx.params = { scope, claims };

      if (ctx.params.claims && typeof ctx.params.claims !== 'string') {
        ctx.params.claims = JSON.stringify(ctx.params.claims);
      }

      for (const cl of clients) {
        const grant = new provider.Grant({ clientId: cl.client_id, accountId });
        grant.addOIDCScope(scope);
        if (ctx.params.claims) {
          grant.addOIDCClaims(Object.keys(JSON.parse(ctx.params.claims).id_token || {}));
          grant.addOIDCClaims(Object.keys(JSON.parse(ctx.params.claims).userinfo || {}));
        }
        if (rejectedScopes.length) {
          grant.rejectOIDCScope(rejectedScopes.join(' '));
        }
        if (rejectedClaims.length) {
          grant.rejectOIDCClaims(rejectedClaims);
        }

        for (const [key, value] of Object.entries(resources)) {
          grant.addResourceScope(key, value);
        }

        const grantId = await grant.save();
        session.authorizations[cl.client_id] = {
          sid: nanoid(),
          grantId,
        };
      }

      let ttl = i(provider).configuration.ttl.Session;

      if (typeof ttl === 'function') {
        ttl = ttl(ctx, session);
      }

      return Account.findAccount({}, accountId).then(session.save(ttl)).then(() => {
        agent._saveCookies.bind(agent)({
          request: { url: provider.issuer },
          headers: { 'set-cookie': cookies },
        });
      });
    }

    class AuthorizationRequest {
      constructor(parameters = {}) {
        if (parameters.claims && typeof parameters.claims !== 'string') {
          parameters.claims = JSON.stringify(parameters.claims); // eslint-disable-line no-param-reassign
        }

        Object.assign(this, parameters);

        this.client_id = 'client_id' in parameters ? parameters.client_id : clients[0].client_id;
        const c = clients.find((cl) => cl.client_id === this.client_id);
        this.state = 'state' in parameters ? parameters.state : crypto.randomBytes(16).toString('base64url');
        this.redirect_uri = 'redirect_uri' in parameters ? parameters.redirect_uri : parameters.redirect_uri || (c && c.redirect_uris[0]);
        this.res = {};

        if (this.response_type && this.response_type.includes('id_token')) {
          this.nonce = 'nonce' in parameters ? parameters.nonce : crypto.randomBytes(16).toString('base64url');
        }

        if (this.response_type && this.response_type.includes('code')) {
          this.code_challenge_method = 'code_challenge_method' in parameters ? parameters.code_challenge_method : 'S256';
          this.code_verifier = crypto.randomBytes(32).toString('base64url');
          this.code_challenge = 'code_challenge' in parameters ? parameters.code_challenge : crypto.hash('sha256', this.code_verifier, 'base64url');
        }

        Object.defineProperty(this, 'validateClientLocation', {
          value: (response) => {
            const actual = parse(response.headers.location, true);
            let expected;
            if (this.redirect_uri) {
              expect(response.headers.location).to.match(new RegExp(this.redirect_uri));
              expected = parse(this.redirect_uri, true);
            } else {
              expect(response.headers.location).to.match(new RegExp(c.redirect_uris[0]));
              expected = parse(c.redirect_uris[0], true);
            }

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

        Object.defineProperty(this, 'validateIss', {
          value: (response) => {
            const { query: { iss } } = parse(response.headers.location, true);
            expect(iss).to.equal(issuerIdentifier);
          },
        });

        Object.defineProperty(this, 'validateInteractionRedirect', {
          value: (response) => {
            const { hostname, search, query } = parse(response.headers.location);
            expect(hostname).to.be.null;
            expect(search).to.be.null;
            expect(query).to.be.null;
            expect(response).to.have.nested.property('headers.set-cookie').that.is.an('array');

            const uid = readCookie(getSetCookies(response)[0]);
            expect(readCookie(getSetCookies(response)[0]))
              .to.equal(readCookie(getSetCookies(response)[1]));

            const interaction = TestAdapter.for('Interaction').syncFind(uid);

            Object.entries(this).forEach(([key, value]) => {
              if (key === 'res') return;
              if (key === 'request') return;
              if (key === 'code_verifier') return;
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

    AuthorizationRequest.prototype.validateInteraction = (eName, ...eReasons) => { // eslint-disable-line arrow-body-style
      return (response) => {
        const uid = readCookie(getSetCookies(response)[0]);
        const { prompt: { name, reasons } } = TestAdapter.for('Interaction').syncFind(uid);
        expect(name).to.equal(eName);
        expect(reasons).to.contain.members(eReasons);
      };
    };

    AuthorizationRequest.prototype.validateFragment = function (response) {
      const { hash } = parse(response.headers.location);
      expect(hash).to.exist;
      response.headers.location = response.headers.location.replace('#', '?'); // eslint-disable-line no-param-reassign
    };

    AuthorizationRequest.prototype.validatePresence = function (properties, all) {
      let absolute;
      if (all === undefined) {
        absolute = true;
      } else {
        absolute = all;
      }

      // eslint-disable-next-line no-param-reassign
      properties = (!absolute || properties.includes('id_token') || properties.includes('response')) ? properties : [...new Set(properties.concat('iss'))];

      return (response) => {
        const { query } = parse(response.headers.location, true);
        if (absolute) {
          expect(query).to.have.keys(properties);
        } else {
          expect(query).to.contain.keys(properties);
        }
        properties.forEach((key) => {
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

    function getLastSession() {
      return lastSession;
    }

    function getSessionId() {
      const { value: sessionId } = agent.jar.getCookie('_session', CookieAccessInfo.All) || {};
      return sessionId;
    }

    function getSession({ instantiate } = { instantiate: false }) {
      const sessionId = getSessionId();
      const raw = TestAdapter.for('Session').syncFind(sessionId);

      if (instantiate) {
        return new provider.Session(raw);
      }

      return raw;
    }

    function getSub() {
      const sessionId = getSessionId();
      const raw = TestAdapter.for('Session').syncFind(sessionId);
      return raw.accountId;
    }

    function getGrantId(client_id) {
      const session = getSession();
      let clientId = client_id;

      if (!clientId && client) clientId = client.client_id;
      if (!clientId && clients) clientId = clients[0].client_id;
      try {
        return session.authorizations[clientId].grantId;
      } catch (err) {
        throw new Error('getGrantId() failed');
      }
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

    function assertOnce(ondone, done) {
      async function removeAfterUse(ctx, next) {
        await next().finally(() => {
          provider.middleware.splice(provider.middleware.indexOf(removeAfterUse), 1);
          try {
            ondone(ctx);
            done();
          } catch (err) {
            done(err);
          }
        });
      }
      provider.use(removeAfterUse);
    }

    function getTokenJti(token) {
      try {
        return jwt(token);
      } catch (err) {}

      return token; // opaque
    }

    function failWith(code, error, error_description, scope, scheme = 'Bearer') {
      return ({ status, body, headers: { 'www-authenticate': wwwAuth } }) => {
        expect(status).to.eql(code);
        expect(body).to.have.property('error', error);
        expect(body).to.have.property('error_description', error_description);
        expect(wwwAuth).to.match(new RegExp(`${scheme} realm="${provider.issuer}"`));
        let check = expect(wwwAuth);
        if (error_description === 'no access token provided') {
          check = check.not.to;
        } else {
          check = check.to;
        }
        check.match(new RegExp(`error="${error}"`));
        check.match(new RegExp(`error_description="${error_description.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}"`));
        if (scope) check.match(new RegExp(`scope="${scope}"`));
      };
    }

    Object.assign(this, {
      assertOnce,
      AuthorizationRequest,
      failWith,
      getLastSession,
      getSession,
      getSessionId,
      getGrantId,
      getSub,
      getTokenJti,
      login,
      logout,
      provider,
      TestAdapter,
      wrap,
      fetchAgent,
      config: mod,
    });

    switch (mountVia) {
      case 'koa': {
        const app = new Koa();
        app.use(koaMount(mountTo, provider));
        globalThis.server.on('request', app.callback());
        this.app = app;
        break;
      }
      case 'express': {
        const app = new Express();
        app.use(mountTo, provider.callback());
        globalThis.server.on('request', app);
        break;
      }
      case 'fastify': {
        const { default: Fastify } = await import('fastify');
        const { default: middie } = await import('@fastify/middie');
        const app = new Fastify();
        await app.register(middie);
        app.use(mountTo, provider.callback());
        await new Promise((resolve) => { globalThis.server.close(resolve); });
        await app.listen({ port, host: '::' });
        globalThis.server = app.server;
        afterPromises.push(async () => {
          await app.close();
          globalThis.server = createServer().listen(port, '::');
          await once(globalThis.server, 'listening');
        });
        break;
      }
      case 'hapi': {
        const { default: Hapi } = await import('@hapi/hapi');
        const app = new Hapi.Server({ port });
        const callback = provider.callback();
        app.route({
          path: `${mountTo}/{any*}`,
          method: '*',
          config: { payload: { output: 'stream', parse: false } },
          async handler({ raw: { req, res } }, h) {
            req.originalUrl = req.url;
            req.url = req.url.replace(mountTo, '');

            callback(req, res);
            await once(res, 'finish');

            req.url = req.url.replace('/', mountTo);
            delete req.originalUrl;

            return res.writableEnded ? h.abandon : h.continue;
          },
        });
        await new Promise((resolve) => { globalThis.server.close(resolve); });
        await app.start();
        globalThis.server = app.listener;
        afterPromises.push(async () => {
          await app.stop();
          globalThis.server = createServer().listen(port, '::');
          await once(globalThis.server, 'listening');
        });
        break;
      }
      default:
        globalThis.server.on('request', provider.callback());
    }

    agent = supertest(globalThis.server);

    if (mountTo !== '/') {
      ['get', 'post', 'put', 'del', 'options', 'trace'].forEach((method) => {
        const orig = agent[method];
        agent[method] = function (route, ...args) {
          if (route.startsWith(mountTo)) {
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
}

export function passInteractionChecks(...reasons) {
  const cb = reasons.pop();

  const sandbox = sinon.createSandbox();

  context('', () => {
    before(function () {
      const { policy } = i(this.provider).configuration.interactions;

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
}

export function skipConsent() {
  const sandbox = sinon.createSandbox();

  before(function () {
    sandbox.stub(this.provider.OIDCContext.prototype, 'promptPending').returns(false);
  });

  after(sandbox.restore);
}

export function enableNetConnect() {
  fetchAgent.enableNetConnect();
}

export function resetNetConnect() {
  fetchAgent.disableNetConnect();
}

export function disableNetConnect() {
  fetchAgent.disableNetConnect();
}

export function assertNoPendingInterceptors() {
  fetchAgent.assertNoPendingInterceptors();
}

export function mock(origin) {
  return fetchAgent.get(origin);
}
