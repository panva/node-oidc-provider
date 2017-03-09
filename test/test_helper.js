'use strict';

/* eslint-disable no-underscore-dangle */

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const mocha = require('mocha');
const coMocha = require('co-mocha');

coMocha(mocha);

const { agent: supertest } = require('supertest');
const { v4: uuid } = require('uuid');
const Provider = require('../lib');
const { Account, TestAdapter } = require('./models');
const { expect } = require('chai');
const { parse } = require('url');
const path = require('path');
const querystring = require('querystring');
const koa = require('koa');
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
  }
};

let base = 33000;
function ephemeralPort() {
  base += 1;
  return base;
}

function jParseCookie(value) {
  expect(value).to.exist;
  const parsed = querystring.parse(value, '; ');
  const key = Object.keys(parsed)[0];
  return JSON.parse(parsed[key]);
}

module.exports = function testHelper(dir, basename, mountTo) {
  const conf = path.format({
    dir,
    base: `${basename || path.basename(dir)}.config.js`,
  });
  let { config, client, clients } = require(conf); // eslint-disable-line
  if (client && !clients) { clients = [client]; }
  config.adapter = TestAdapter;
  config.findById = Account.findById;

  const port = ephemeralPort();

  const provider = new Provider(`http://127.0.0.1:${port}${mountTo || ''}`, config);
  provider.defaultHttpOptions = { timeout: 50 };

  let server;
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

    return Account.findById(account).then(session.save()).then(() => {
      agent._saveCookies.bind(agent)({ headers: { 'set-cookie': cookies } });
    });
  }

  function AuthorizationRequest(parameters) {
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
        expect(response).to.have.deep.property('headers.set-cookie').that.is.an('array');

        const interaction = jParseCookie(response.headers['set-cookie'][1]);
        const respond = jParseCookie(response.headers['set-cookie'][2]);

        for (const attr in this) { // eslint-disable-line
          if (this.hasOwnProperty(attr)) { // eslint-disable-line
            expect(respond).to.have.property(attr, this[attr]);
            expect(interaction.params).to.have.property(attr, this[attr]);
          }
        }
      }
    });
  }

  AuthorizationRequest.prototype.validateInteractionError = function (expectedError, expectedReason) {
    return (response) => {
      const { interaction: { error, reason } } = jParseCookie(response.headers['set-cookie'][1]);
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

  function getSession() {
    const { value: sessionId } = agent.jar.getCookie('_session', { path: '/' });
    const key = TestAdapter.for('Session').key(sessionId);
    return TestAdapter.for('Session').get(key);
  }

  function getSessionId() {
    const { value: sessionId } = agent.jar.getCookie('_session', { path: '/' });
    return sessionId;
  }

  function wrap(opts) {
    const { route, verb, auth, params } = opts; // eslint-disable-line no-shadow
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

  after(function (done) {
    server.close(done);
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
      TestAdapter
    });

    return new Promise((resolve, reject) => {
      provider.initialize({
        clients,
        keystore: global.keystore,
      }).then(() => {
        if (mountTo) {
          const app = koa();
          app.use(mount(mountTo, provider.app));
          server = app.listen(port);
        } else {
          server = provider.app.listen(port);
        }

        agent = supertest(server);
        this.agent = agent;
      }, reject).then(resolve);
    }).catch((err) => {
      console.error(err); // eslint-disable-line no-console
      throw err;
    });
  };
};
