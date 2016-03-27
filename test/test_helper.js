'use strict';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

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
  }
};

module.exports = function(dir, basename) {
  let conf = path.format({
    dir,
    base: `${basename || path.basename(dir)}.config.js`
  });
  let { config, certs, client } = require(conf);
  let provider = new Provider('http://127.0.0.1', { config });
  provider.Account = Account;

  provider.configuration.adapters.TestAdapter = TestAdapter;
  provider.configuration.adapter = 'TestAdapter';

  // gotta delegate the keystore object so that i can stub the method calls
  // with sinon
  let store = jose.JWK.createKeyStore();
  let delegatedStore = { store };
  delegate(delegatedStore, 'store')
    .method('toJSON')
    .method('add')
    .method('remove')
    .method('get');
  provider.keystore = delegatedStore;

  let server = provider.app.listen();
  let agent = supertest(server);

  provider.issuer = `http://127.0.0.1:${server.address().port}`;

  agent.logout = function() {
    const expire = new Date(0);
    return agent.saveCookies({
      headers: {
        'set-cookie': [
          `_session=; path=/; expires=${expire.toGMTString()}; httponly`
        ]
      }
    });
  };

  agent.login = function() {
    const sessionId = uuid();
    const loginTs = new Date() / 1000 | 0;
    const expire = new Date();
    expire.setDate(expire.getDate() + 1);
    const account = uuid();

    let session = new provider.Session(sessionId, { loginTs, account });

    return Account.findById(account).then(session.save()).then(() => {
      agent.saveCookies({
        headers: {
          'set-cookie': [
            `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`
          ]
        }
      });
    });
  };

  function AuthenticationRequest(query) {
    this.client_id = client.client_id;
    this.state = Math.random().toString();
    this.nonce = Math.random().toString();
    this.redirect_uri = client.redirect_uris[0];

    Object.assign(this, query);

    Object.defineProperty(this, 'validateClientLocation', {
      value: (response) => {
        let expected = parse(this.redirect_uri, true);
        let actual = parse(response.headers.location, true);
        ['protocol', 'host', 'pathname'].forEach((attr) => {
          expect(actual[attr]).to.equal(expected[attr]);
        });
      }
    });

    Object.defineProperty(this, 'validateState', {
      value: (response) => {
        let { query: { state } } = parse(response.headers.location, true);
        expect(state).to.equal(this.state);
      }
    });

    Object.defineProperty(this, 'validateInteractionRedirect', {
      value: (response) => {
        let { hostname, search, query } = parse(response.headers.location);
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

        for (var attr in this) {
          if (this.hasOwnProperty(attr)) {
            expect(respond).to.have.property(attr, this[attr]);
            expect(interaction.params).to.have.property(attr, this[attr]);
          }
        }
      }
    });
  }

  AuthenticationRequest.prototype.validateInteractionError = function(expectedError, expectedReason) {
    return (response) => {
      let value = response.headers['set-cookie'][1];
      let { value: interaction } = new Cookie(value);
      let { details: { error, reason } } = JSON.parse(interaction);

      expect(error).to.equal(expectedError);
      expect(reason).to.equal(expectedReason);
    };
  };

  AuthenticationRequest.prototype.validateFragment = function(response) {
    let { hash } = parse(response.headers.location);
    expect(hash).to.exist;
    response.headers.location = response.headers.location.replace('#', '?');
  };

  AuthenticationRequest.prototype.validatePresence = function(keys) {
    return (response) => {
      let { query } = parse(response.headers.location, true);
      expect(query).to.have.all.keys(keys);
    };
  };

  AuthenticationRequest.prototype.validateError = function(expected) {
    return (response) => {
      let { query: { error } } = parse(response.headers.location, true);
      expect(error).to.equal(expected);
    };
  };

  AuthenticationRequest.prototype.validateErrorDescription = function(expected) {
    return (response) => {
      let { query: { error_description } } = parse(response.headers.location, true);
      expect(error_description).to.equal(expected);
    };
  };

  provider.setupClient = function() {
    const self = this;
    before('adding client', function() {
      return self.Client.add(client);
    });

    after('removing client', function() {
      self.Client.remove(client.client_id);
    });
  };

  provider.setupCerts = function(passed) {
    const self = this;
    const pre = _.pick(self.configuration, [
      'requestObjectEncryptionAlgValuesSupported',
      'idTokenSigningAlgValuesSupported',
      'userinfoSigningAlgValuesSupported'
    ]);
    const added = [];

    before('adding certificate', function(done) {
      let add = passed || certs;
      let promises = add.map(cert => self.addKey(cert).then((key) => {
        return added.push(key);
      }));
      Promise.all(promises).then(() => {
        done();
      }, done);
    });

    after('removing certificate', function() {
      _.assign(self.configuration, pre);
      added.forEach(key => self.keystore.remove(key));
    });
  };

  function getSession(agent) {
    let { value: sessionId } = agent.jar.getCookie('_session', { path: '/' });
    let key = provider.Session.adapter.key(sessionId);
    return provider.Session.adapter.storage.get(key);
  }

  function wrap(opts) {
    let { agent, route, verb, auth } = opts;
    switch (verb) {
      case 'get':
        return agent
          .get(route)
          .query(auth);
      case 'post':
        return agent
          .post(route)
          .send(auth)
          .set('Content-Type', 'application/x-www-form-urlencoded');
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
