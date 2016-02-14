'use strict';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const { agent: supertest } = require('supertest');
const { v4: uuid } = require('uuid');
const { Provider } = require('../lib');
const { Account } = require('./models');
const { expect } = require('chai');
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
    name: basename || path.basename(dir),
    ext: '.config.js'
  });
  let { config, certs, client } = require(conf);
  let provider = new Provider('http://127.0.0.1', { config });
  provider.Account = Account;

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
    before(function() {
      const expire = new Date(0);
      agent.saveCookies({
        headers: {
          'set-cookie': [
            `_session=; path=/; expires=${expire.toGMTString()}; httponly`
          ]
        }
      });
    });
  };

  agent.login = function() {
    const sessionId = uuid();
    const loginTs = new Date() / 1000 | 0;
    const expire = new Date();
    expire.setDate(expire.getDate() + 1);
    const account = uuid();

    before(function() {
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
    });

    return account;
  };

  function AuthenticationRequest(query) {
    this.client_id = client.client_id;
    this.response_type = 'code';
    this.scope = 'openid';
    this.state = Math.random().toString();
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
  }

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

  function setupClient() {
    before('adding client', function() {
      return provider.Client.add(client);
    });

    after('removing client', function() {
      provider.Client.remove(client.client_id);
    });
  };

  function setupCerts(passed) {
    const pre = _.pick(provider.configuration, [
      'requestObjectEncryptionAlgValuesSupported',
      'idTokenSigningAlgValuesSupported',
      'userinfoSigningAlgValuesSupported'
    ]);
    const added = [];

    before('adding certificate', function(done) {
      let add = passed || certs;
      let promises = add.map(cert => provider.addKey(cert).then((key) => {
        return added.push(key);
      }));
      Promise.all(promises).then(() => {
        done();
      }, done);
    });

    after('removing certificate', function() {
      _.assign(provider.configuration, pre);
      added.forEach(key => provider.keystore.remove(key));
    });
  };

  return {
    AuthenticationRequest,
    provider,
    agent,
    server,
    config,
    responses,
    client,
    certs,
    setupClient,
    setupCerts
  };
};
