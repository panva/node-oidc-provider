'use strict';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const mocha = require('mocha');
const coMocha = require('co-mocha');

coMocha(mocha);

const { agent: supertest } = require('supertest');
const { v4: uuid } = require('node-uuid');
const { Provider } = require('../lib');
const { Account, TestAdapter } = require('./models');
const { expect } = require('chai');
const { Cookie } = require('cookiejar');
const { parse } = require('url');
const path = require('path');
const jose = require('node-jose');
const delegate = require('delegates');
const _ = require('lodash');
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

module.exports = function testHelper(dir, basename) {
  const conf = path.format({
    dir,
    base: `${basename || path.basename(dir)}.config.js`,
  });
  const { config, certs, client } = require(conf); // eslint-disable-line global-require
  config.adapter = TestAdapter;
  const provider = new Provider('http://127.0.0.1', config);
  provider.Account = Account;

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

  const server = provider.app.listen();
  const agent = supertest(server);

  provider.issuer = `http://127.0.0.1:${server.address().port}`;

  agent.logout = function logout() {
    const expire = new Date(0);
    return agent.saveCookies({
      headers: {
        'set-cookie': [
          `_session=; path=/; expires=${expire.toGMTString()}; httponly`,
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

    const session = new provider.Session(sessionId, { loginTs, account });

    return Account.findById(account).then(session.save()).then(() => {
      agent.saveCookies({
        headers: {
          'set-cookie': [
            `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`,
          ],
        },
      });
    });
  };

  function AuthenticationRequest(parameters) {
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
          if (this.hasOwnProperty(attr)) {
            expect(respond).to.have.property(attr, this[attr]);
            expect(interaction.params).to.have.property(attr, this[attr]);
          }
        }
      }
    });
  }

  AuthenticationRequest.prototype.validateInteractionError = function (expectedError, expectedReason) {
    return (response) => {
      const value = response.headers['set-cookie'][1];
      const { value: interaction } = new Cookie(value);
      const { details: { error, reason } } = JSON.parse(interaction);

      expect(error).to.equal(expectedError);
      expect(reason).to.equal(expectedReason);
    };
  };

  AuthenticationRequest.prototype.validateFragment = function (response) {
    const { hash } = parse(response.headers.location);
    expect(hash).to.exist;
    response.headers.location = response.headers.location.replace('#', '?');
  };

  AuthenticationRequest.prototype.validatePresence = function (keys, all) {
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

  AuthenticationRequest.prototype.validateError = function (expected) {
    return (response) => {
      const { query: { error } } = parse(response.headers.location, true);
      expect(error).to.equal(expected);
    };
  };

  AuthenticationRequest.prototype.validateErrorDescription = function (expected) {
    return (response) => {
      const { query: { error_description } } = parse(response.headers.location, true);
      expect(error_description).to.equal(expected);
    };
  };

  provider.setupClient = function setupClient(pass) {
    const self = this;
    const add = pass || client;
    before('adding client', () => self.addClient(add));
    after('removing client', () => self.Client.remove(add.client_id));
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
    const { value: sessionId } = userAgent.jar.getCookie('_session', { path: '/' });
    const key = provider.Session.adapter.key(sessionId);
    return provider.Session.adapter.storage.get(key);
  }

  function wrap(opts) {
    const { agent, route, verb, auth } = opts; // eslint-disable-line no-shadow
    switch (verb) {
      case 'get':
        return agent
          .get(route)
          .query(auth);
      case 'post':
        return agent
          .post(route)
          .send(auth)
          .type('form');
      default:
        throw new Error('invalid wrap verb');
    }
  }

  return {
    AuthenticationRequest,
    provider,
    agent,
    responses,
    getSession,
    wrap
  };
};
