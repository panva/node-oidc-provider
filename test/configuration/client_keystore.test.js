'use strict';

const keystore = require('node-jose').JWK.createKeyStore();
const moment = require('moment');
const nock = require('nock');
const { expect } = require('chai');
const JWT = require('../../lib/helpers/jwt');
const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const fail = () => { throw new Error('expected promise to be rejected'); };

const endpoint = nock('https://client.example.com/');

describe('client keystore refresh', () => {
  const { provider } = bootstrap(__dirname);


  before(() => {
    return keystore.generate('RSA', 1024).then(() => {
      endpoint
        .get('/jwks')
        .reply(200, JSON.stringify(keystore.toJSON()));
    });
  });

  before(() => {
    return provider.addClient({
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      jwks_uri: 'https://client.example.com/jwks',
      id_token_signed_response_alg: 'none',
      id_token_encrypted_response_alg: 'RSA1_5',
      id_token_encrypted_response_enc: 'A128CBC-HS256',
    });
  });

  it('gets the jwks from the uri', function* () {
    const client = yield provider.Client.find('client');
    expect(client.keystore.get({ kty: 'RSA' })).to.be.ok;
  });

  it('adds new keys', function* () {
    const client = yield provider.Client.find('client');
    yield keystore.generate('RSA', 1024);
    endpoint
      .get('/jwks')
      .reply(200, keystore.toJSON());

    return client.keystore.refresh().then(() => {
      expect(client.keystore.all({ kty: 'RSA' })).to.have.lengthOf(2);
    });
  });

  it('removes not found keys', function* () {
    endpoint
      .get('/jwks')
      .reply(200, '{"keys":[]}');

    const client = yield provider.Client.find('client');
    return client.keystore.refresh().then(() => {
      expect(client.keystore.get({ kty: 'RSA' })).not.to.be.ok;
    });
  });

  it('only accepts 200s', function* () {
    endpoint
      .get('/jwks')
      .reply(302, '/somewhere');

    const client = yield provider.Client.find('client');
    return client.keystore.refresh().then(fail, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.match(/jwks_uri could not be refreshed/);
      expect(err.message).to.match(/unexpected jwks_uri statusCode, expected 200, got 302/);
    });
  });

  it('only accepts parseable json', function* () {
    endpoint
      .get('/jwks')
      .reply(200, 'not json');

    const client = yield provider.Client.find('client');
    return client.keystore.refresh().then(fail, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.match(/jwks_uri could not be refreshed/);
      expect(err.message).to.match(/Unexpected token/);
    });
  });

  it('only accepts keys as array', function* () {
    endpoint
      .get('/jwks')
      .reply(200, '{"keys": {}}');

    const client = yield provider.Client.find('client');
    return client.keystore.refresh().then(fail, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.match(/jwks_uri could not be refreshed/);
      expect(err.message).to.match(/invalid jwks_uri response/);
    });
  });

  describe('caching', () => {
    it('uses expires caching header to determine stale states', function* () {
      const client = yield provider.Client.find('client');
      yield keystore.generate('RSA', 1024);
      const until = moment().add(2, 'hours').toDate();

      endpoint
        .get('/jwks')
        .reply(200, keystore.toJSON(), {
          Expires: until.toUTCString()
        });

      return client.keystore.refresh().then(() => {
        expect(client.keystore.fresh()).to.be.true;
        expect(client.keystore.stale()).to.be.false;
        expect(client.keystore.freshUntil).to.equal(epochTime(until));
      });
    });

    it('ignores the cache-control one when expires is provided', function* () {
      const client = yield provider.Client.find('client');
      yield keystore.generate('RSA', 1024);
      const until = moment().add(2, 'hours').toDate();

      endpoint
        .get('/jwks')
        .reply(200, keystore.toJSON(), {
          Expires: until.toUTCString(),
          'Cache-Control': 'private, max-age: 3600'
        });

      return client.keystore.refresh().then(() => {
        expect(client.keystore.fresh()).to.be.true;
        expect(client.keystore.stale()).to.be.false;
        expect(client.keystore.freshUntil).to.equal(epochTime(until));
      });
    });

    it('uses the max-age if Cache-Control is missing', function* () {
      const client = yield provider.Client.find('client');
      yield keystore.generate('RSA', 1024);

      endpoint
        .get('/jwks')
        .reply(200, keystore.toJSON(), {
          'Cache-Control': 'private, max-age=3600'
        });

      return client.keystore.refresh().then(() => {
        expect(client.keystore.fresh()).to.be.true;
        expect(client.keystore.stale()).to.be.false;
        expect(client.keystore.freshUntil).to.equal(epochTime() + 3600);
      });
    });

    it('falls back to 1 minute throttle if no caching header is found', function* () {
      const client = yield provider.Client.find('client');
      yield keystore.generate('RSA', 1024);

      endpoint
        .get('/jwks')
        .reply(200, keystore.toJSON());

      return client.keystore.refresh().then(() => {
        expect(client.keystore.fresh()).to.be.true;
        expect(client.keystore.stale()).to.be.false;
        expect(client.keystore.freshUntil).to.equal(epochTime() + 60);
      });
    });
  });

  describe('refreshing', () => {
    it('when a stale keystore is passed to JWT verification it gets refreshed', function* () {
      endpoint
        .get('/jwks')
        .reply(200, keystore.toJSON());

      expect(nock.isDone()).to.be.false;

      const client = yield provider.Client.find('client');
      client.keystore.freshUntil = epochTime() - 1;
      return JWT.verify(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
      , client.keystore).then(fail, () => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('refreshes stale keystores before id_token encryption', function* () {
      endpoint
        .get('/jwks')
        .reply(200, keystore.toJSON());

      expect(nock.isDone()).to.be.false;

      const client = yield provider.Client.find('client');
      client.keystore.freshUntil = epochTime() - 1;

      const IdToken = provider.IdToken;
      const token = new IdToken({ foo: 'bar' });

      return token.sign(client).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });
  });
});
