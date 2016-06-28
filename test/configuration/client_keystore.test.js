'use strict';

const keystore = require('node-jose').JWK.createKeyStore();
const { provider } = require('../test_helper')(__dirname);
const nock = require('nock');
const { expect } = require('chai');
const endpoint = nock('https://client.example.com/');

describe('client keystore refresh', function () {
  provider.setupCerts();

  before(function () {
    return keystore.generate('RSA', 1024).then(function () {
      endpoint
        .get('/jwks')
        .reply(200, JSON.stringify(keystore.toJSON()));
    });
  });

  before(function () {
    return provider.addClient({
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      jwks_uri: 'https://client.example.com/jwks'
    });
  });

  it('gets the jwks from the uri', function * () {
    const client = yield provider.get('Client').find('client');
    expect(client.keystore.get({ kty: 'RSA' })).to.be.ok;
  });

  it('adds new keys', function * () {
    const client = yield provider.get('Client').find('client');
    yield keystore.generate('RSA', 1024);
    endpoint
      .get('/jwks')
      .reply(200, keystore.toJSON());

    return client.keystore.refresh().then(function () {
      expect(client.keystore.all({ kty: 'RSA' })).to.have.lengthOf(2);
    });
  });

  it('removes not found keys', function * () {
    endpoint
      .get('/jwks')
      .reply(200, '{"keys":[]}');

    const client = yield provider.get('Client').find('client');
    return client.keystore.refresh().then(function () {
      expect(client.keystore.get({ kty: 'RSA' })).not.to.be.ok;
    });
  });

  it('only accepts 200s', function * () {
    endpoint
      .get('/jwks')
      .reply(302, '/somewhere');

    const client = yield provider.get('Client').find('client');
    return client.keystore.refresh().then(() => {
      throw new Error('expected refresh to be rejected');
    }, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.match(/jwks_uri could not be refreshed/);
      expect(err.message).to.match(/unexpected jwks_uri statusCode, expected 200, got 302/);
    });
  });

  it('only accepts parseable json', function * () {
    endpoint
      .get('/jwks')
      .reply(200, 'not json');

    const client = yield provider.get('Client').find('client');
    return client.keystore.refresh().then(() => {
      throw new Error('expected refresh to be rejected');
    }, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.match(/jwks_uri could not be refreshed/);
      expect(err.message).to.match(/Unexpected token/);
    });
  });

  it('only accepts keys as array', function * () {
    endpoint
      .get('/jwks')
      .reply(200, '{"keys": {}}');

    const client = yield provider.get('Client').find('client');
    return client.keystore.refresh().then(() => {
      throw new Error('expected refresh to be rejected');
    }, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.match(/jwks_uri could not be refreshed/);
      expect(err.message).to.match(/invalid jwks_uri response/);
    });
  });
});
