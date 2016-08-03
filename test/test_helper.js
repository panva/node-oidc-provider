'use strict';

/* eslint-disable no-underscore-dangle */

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const mocha = require('mocha');
const coMocha = require('co-mocha');

coMocha(mocha);

const { agent: supertest } = require('supertest');
const { v4: uuid } = require('uuid');
const { Provider } = require('../lib');
const { Account, TestAdapter } = require('./models');
const { expect } = require('chai');
const { Cookie } = require('cookiejar');
const { parse } = require('url');
const path = require('path');
const jose = require('node-jose');
const delegate = require('delegates');
const _ = require('lodash');
const koa = require('koa');
const mount = require('koa-mount');

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

module.exports = function testHelper(dir, basename, mountTo) {
  const conf = path.format({
    dir,
    base: `${basename || path.basename(dir)}.config.js`,
  });
  const { config, certs, client } = require(conf); // eslint-disable-line global-require
  config.adapter = TestAdapter;
  config.findById = Account.findById;
  const provider = new Provider(`http://127.0.0.1${mountTo || ''}`, config);

  // gotta delegate the keystore object so that we can stub the method calls
  // with sinon
  const store = jose.JWK.createKeyStore();
  const delegatedStore = { store };
  delegate(delegatedStore, 'store')
    .method('toJSON')
    .method('add')
    .method('all')
    .method('generate')
    .method('remove')
    .method('get');
  provider.keystore = delegatedStore;

  let server;

  if (mountTo) {
    const app = koa();
    app.use(mount(mountTo, provider.app));
    server = app.listen();
  } else {
    server = provider.app.listen();
  }

  const agent = supertest(server);

  provider.issuer = `http://127.0.0.1:${server.address().port}${mountTo || ''}`;

  agent.logout = function logout() {
    const expire = new Date(0);
    return agent._saveCookies.bind(agent)({
      headers: {
        'set-cookie': [
          `_session=; path=/; expires=${expire.toGMTString()}; httponly`,
          `_session.sig=; path=/; expires=${expire.toGMTString()}; httponly`,
          `_session_states=; path=/; expires=${expire.toGMTString()}; httponly`,
          `_session_states.sig=; path=/; expires=${expire.toGMTString()}; httponly`,
        ],
      },
    });
  };

  agent.login = function login() {
    const sessionId = uuid();
    const loginTs = new Date() / 1000 | 0;
    const expire = new Date();
    expire.setDate(expire.getDate() + 1);
    const account = uuid();

    const session = new (provider.get('Session'))(sessionId, { loginTs, account });
    const cookies = [`_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`];

    if (provider.configuration('features.sessionManagement')) {
      cookies.push(`_session_states=${JSON.stringify({ [client.client_id]: String(loginTs) })}; path=/; expires=${expire.toGMTString()};`);
    }

    return Account.findById(account).then(session.save()).then(() => {
      agent._saveCookies.bind(agent)({
        headers: {
          'set-cookie': cookies,
        },
      });
    });
  };

  function AuthorizationRequest(parameters) {
    this.client_id = client.client_id;
    this.state = Math.random().toString();
    this.nonce = Math.random().toString();
    this.redirect_uri = client.redirect_uris[0];

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

        let value = response.headers['set-cookie'][1];
        // validate the interaction route has the cookie set
        expect(value).to.exist;
        let { value: interaction } = new Cookie(value);
        interaction = JSON.parse(interaction);

        value = response.headers['set-cookie'][2];
        // validate the interaction route has the cookie set
        expect(value).to.exist;
        let { value: respond } = new Cookie(value);
        respond = JSON.parse(respond);

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
      const setCookie = response.headers['set-cookie'][1];
      const { value: interaction } = new Cookie(setCookie);
      const { interaction: { error, reason } } = JSON.parse(interaction);

      expect(error).to.equal(expectedError);
      expect(reason).to.equal(expectedReason);
    };
  };

  AuthorizationRequest.prototype.validateFragment = function (response) {
    const { hash } = parse(response.headers.location);
    expect(hash).to.exist;
    response.headers.location = response.headers.location.replace('#', '?');
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

  provider.setupClient = function setupClient(pass) {
    if (provider.configuration('idTokenSigningAlgValues').indexOf('RS256') === -1) {
      this.setupCerts();
    }

    const add = pass || client;
    before('adding client', function () {
      return provider.addClient(add).catch((err) => {
        throw err;
      });
    });

    after('removing client', function () {
      return provider.get('Client').remove(add.client_id);
    });
  };

  provider.setupCerts = function (passed) {
    const self = this;
    const pre = _.pick(self.configuration, [
      'requestObjectEncryptionAlgValues',
      'idTokenSigningAlgValues',
      'userinfoSigningAlgValues'
    ]);
    const added = [];

    before('adding certificate', function (done) {
      const add = passed || certs;
      const promises = add.map(cert => self.addKey(cert).then((key) => added.push(key)));
      Promise.all(promises).then(() => {
        done();
      }, done);
    });

    after('removing certificate', function () {
      _.assign(self.configuration, pre);
      added.forEach(key => self.keystore.remove(key));
    });
  };

  function getSession(userAgent) {
    const Session = provider.get('Session');
    const { value: sessionId } = userAgent.jar.getCookie('_session', { path: '/' });
    const key = Session.adapter.key(sessionId);
    return Session.adapter.storage.get(key);
  }

  function getSessionId(userAgent) {
    const { value: sessionId } = userAgent.jar.getCookie('_session', { path: '/' });
    return sessionId;
  }

  function wrap(opts) {
    const { agent, route, verb, auth, params } = opts; // eslint-disable-line no-shadow
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

  return {
    AuthorizationRequest,
    provider,
    agent,
    responses,
    getSessionId,
    getSession,
    wrap
  };
};
