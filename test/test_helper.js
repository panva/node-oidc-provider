/* eslint-disable no-underscore-dangle */

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const { agent: supertest } = require('supertest');
const uuid = require('uuid/v4');
const Provider = require('../lib');
const { Account, TestAdapter } = require('./models');
const { expect } = require('chai');
const { parse } = require('url');
const path = require('path');
const Koa = require('koa');
const querystring = require('querystring');
const mount = require('koa-mount');
const epochTime = require('../lib/helpers/epoch_time');
global.instance = require('../lib/helpers/weak_cache');

global.i = instance;

const responses = {
  serverErrorBody: {
    error: 'server_error',
    error_description: 'oops something went wrong',
  },
  tokenAuthSucceeded: {
    error: 'restricted_grant_type',
    error_description: 'requested grant type is restricted to this client',
  },
  tokenAuthRejected: {
    error: 'invalid_client',
    error_description: 'client is invalid',
  },
};

function readCookie(value) {
  expect(value).to.exist;
  const parsed = querystring.parse(value, '; ');
  const key = Object.keys(parsed)[0];
  return parsed[key];
}

const { port } = global.server.address();

module.exports = function testHelper(dir, basename, mountTo) {
  const conf = path.format({
    dir,
    base: `${basename || path.basename(dir)}.config.js`,
  });
  let { config, client, clients } = require(conf); // eslint-disable-line
  if (client && !clients) { clients = [client]; }
  if (!config.findById) config.findById = Account.findById;

  const provider = new Provider(`http://127.0.0.1:${port}${mountTo || ''}`, config);
  provider.defaultHttpOptions = { timeout: 50 };

  let agent;

  function logout() {
    const expire = new Date(0);
    const cookies = [
      `_session=; path=/; expires=${expire.toGMTString()}; httponly`,
      `_session.sig=; path=/; expires=${expire.toGMTString()}; httponly`,
    ];

    clients.forEach((cl) => {
      cookies.push(`_state.${cl.client_id}=; path=/; expires=${expire.toGMTString()}; httponly`);
      cookies.push(`_state.${cl.client_id}.sig=; path=/; expires=${expire.toGMTString()}; httponly`);
    });

    return agent._saveCookies.bind(agent)({ headers: { 'set-cookie': cookies } });
  }

  function login() {
    const sessionId = uuid();
    const loginTs = epochTime();
    const expire = new Date();
    expire.setDate(expire.getDate() + 1);
    const account = uuid();
    this.loggedInAccountId = account;

    const session = new (provider.Session)(sessionId, { loginTs, account });
    const cookies = [`_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`];

    session.authorizations = {};
    clients.forEach((cl) => {
      session.authorizations[cl.client_id] = { sid: uuid() };
      if (i(provider).configuration('features.sessionManagement')) {
        cookies.push(`_state.${cl.client_id}=${loginTs}; path=/; expires=${expire.toGMTString()};`);
      }
    });

    return Account.findById({}, account).then(session.save()).then(() => {
      agent._saveCookies.bind(agent)({ headers: { 'set-cookie': cookies } });
    });
  }

  class AuthorizationRequest {
    constructor(parameters) {
      this.client_id = parameters.client_id || clients[0].client_id;
      this.state = Math.random().toString();
      this.nonce = Math.random().toString();
      this.redirect_uri = parameters.redirect_uri || clients[0].redirect_uris[0];

      Object.assign(this, parameters);

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

          const grantid = readCookie(response.headers['set-cookie'][1]);
          expect(readCookie(response.headers['set-cookie'][1])).to.equal(readCookie(response.headers['set-cookie'][2]));

          const interaction = TestAdapter.for('Session').syncFind(grantid);

          Object.entries(this).forEach(([key, value]) => {
            expect(interaction.params).to.have.property(key, value);
          });
        },
      });
    }
  }

  AuthorizationRequest.prototype.validateInteractionError = (expectedError, expectedReason) => { // eslint-disable-line arrow-body-style, max-len
    return (response) => {
      const grantid = readCookie(response.headers['set-cookie'][1]);
      const { interaction: { error, reason } } = TestAdapter.for('Session').syncFind(grantid);
      expect(error).to.equal(expectedError);
      expect(reason).to.equal(expectedReason);
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
    };
  };

  AuthorizationRequest.prototype.validateError = function (expected) {
    return (response) => {
      const { query: { error } } = parse(response.headers.location, true);
      if (expected.exec) {
        expect(error).to.match(expected);
      } else {
        expect(error).to.equal(expected);
      }
    };
  };

  AuthorizationRequest.prototype.validateErrorDescription = function (expected) {
    return (response) => {
      const { query: { error_description } } = parse(response.headers.location, true);
      if (expected.exec) {
        expect(error_description).to.match(expected);
      } else {
        expect(error_description).to.equal(expected);
      }
    };
  };

  function getSession(opts = { instantiate: false }) {
    const { value: sessionId } = agent.jar.getCookie('_session', { path: '/' });
    const key = TestAdapter.for('Session').key(sessionId);
    const raw = TestAdapter.for('Session').get(key);

    if (opts.instantiate) {
      return raw ? new provider.Session(sessionId, raw) : raw;
    }

    return raw;
  }

  function getSessionId() {
    const { value: sessionId } = agent.jar.getCookie('_session', { path: '/' });
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

  after(() => {
    global.server.removeAllListeners('request');
  });

  return function () {
    Object.assign(this, {
      login,
      logout,
      AuthorizationRequest,
      provider,
      responses,
      getSessionId,
      getSession,
      wrap,
      TestAdapter,
    });

    return new Promise((resolve, reject) => {
      provider.initialize({
        clients,
        adapter: TestAdapter,
        keystore: global.keystore,
      }).then(() => {
        if (mountTo) {
          const app = new Koa();
          app.use(mount(mountTo, provider.app));
          global.server.on('request', app.callback());
        } else {
          global.server.on('request', provider.callback);
        }

        agent = supertest(global.server);
        this.agent = agent;
      }, reject).then(resolve);
    }).catch((err) => {
      console.error(err); // eslint-disable-line no-console
      throw err;
    });
  };
};
