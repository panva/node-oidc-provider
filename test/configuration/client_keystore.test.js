const assert = require('assert');

const keystore = require('node-jose').JWK.createKeyStore();
const moment = require('moment');
const nock = require('nock');
const sinon = require('sinon');
const { expect } = require('chai');

const JWT = require('../../lib/helpers/jwt');
const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const fail = () => { throw new Error('expected promise to be rejected'); };

const endpoint = nock('https://client.example.com/');

function setResponse(body = keystore.toJSON(), statusCode = 200, headers = {}) {
  endpoint
    .get('/jwks')
    .reply(statusCode, typeof body === 'string' ? body : JSON.stringify(body), headers);
  assert(!nock.isDone(), 'expected client\'s jwks_uri to be fetched');
}

describe('client keystore refresh', () => {
  afterEach(() => {
    expect(nock.isDone()).to.be.true;
  });

  before(bootstrap(__dirname, { config: 'client_keystore' }));

  before(async function () {
    return i(this.provider).clientAdd({
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      jwks_uri: 'https://client.example.com/jwks',
      id_token_signed_response_alg: 'none',
      id_token_encrypted_response_alg: 'ECDH-ES+A128KW',
      id_token_encrypted_response_enc: 'A128CBC-HS256',
    });
  });

  afterEach(async function () {
    const client = await this.provider.Client.find('client');
    if (client.keystore.fresh.restore) client.keystore.fresh.restore();
  });

  it('gets the jwks from the uri', async function () {
    await keystore.generate('EC', 'P-256');
    setResponse();

    const client = await this.provider.Client.find('client');
    await client.keystore.refresh();

    expect(client.keystore.get({ kty: 'EC' })).to.be.ok;
  });

  it('adds new keys', async function () {
    const client = await this.provider.Client.find('client');
    await keystore.generate('EC', 'P-256');
    setResponse();

    sinon.stub(client.keystore, 'fresh').returns(false);
    await client.keystore.refresh();
    expect(client.keystore.all({ kty: 'EC' })).to.have.lengthOf(2);
  });

  it('removes not found keys', async function () {
    setResponse({ keys: [] });

    const client = await this.provider.Client.find('client');
    sinon.stub(client.keystore, 'fresh').returns(false);
    await client.keystore.refresh();

    expect(client.keystore.get({ kty: 'EC' })).not.to.be.ok;
  });

  it('only accepts 200s', async function () {
    setResponse('/somewhere', 302);

    const client = await this.provider.Client.find('client');
    sinon.stub(client.keystore, 'fresh').returns(false);
    await client.keystore.refresh().then(fail, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.equal('invalid_client_metadata');
      expect(err.error_description).to.match(/jwks_uri could not be refreshed/);
      expect(err.error_description).to.match(/unexpected jwks_uri statusCode, expected 200, got 302/);
    });
  });

  it('only accepts parseable json', async function () {
    setResponse('not json');

    const client = await this.provider.Client.find('client');
    sinon.stub(client.keystore, 'fresh').returns(false);
    await client.keystore.refresh().then(fail, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.equal('invalid_client_metadata');
      expect(err.error_description).to.match(/jwks_uri could not be refreshed/);
      expect(err.error_description).to.match(/Unexpected token/);
    });
  });

  it('only accepts keys as array', async function () {
    setResponse({ keys: {} });

    const client = await this.provider.Client.find('client');
    sinon.stub(client.keystore, 'fresh').returns(false);
    await client.keystore.refresh().then(fail, (err) => {
      expect(err).to.be.an('error');
      expect(err.message).to.equal('invalid_client_metadata');
      expect(err.error_description).to.match(/jwks_uri could not be refreshed/);
      expect(err.error_description).to.match(/invalid jwks_uri response/);
    });
  });

  describe('caching', () => {
    it('uses expires caching header to determine stale states', async function () {
      const client = await this.provider.Client.find('client');
      await keystore.generate('EC', 'P-256');
      const until = moment().add(2, 'hours').toDate();

      setResponse(undefined, undefined, {
        Expires: until.toUTCString(),
      });

      const freshUntil = epochTime(until);

      sinon.stub(client.keystore, 'fresh').callsFake(function () {
        this.fresh.restore();
        return false;
      });
      await client.keystore.refresh();
      expect(client.keystore.fresh()).to.be.true;
      expect(client.keystore.stale()).to.be.false;
      expect(client.keystore.freshUntil).to.equal(freshUntil);
    });

    it('ignores the cache-control one when expires is provided', async function () {
      const client = await this.provider.Client.find('client');
      await keystore.generate('EC', 'P-256');
      const until = moment().add(2, 'hours').toDate();

      setResponse(undefined, undefined, {
        Expires: until.toUTCString(),
        'Cache-Control': 'private, max-age: 3600',
      });

      const freshUntil = epochTime(until);

      sinon.stub(client.keystore, 'fresh').callsFake(function () {
        this.fresh.restore();
        return false;
      });
      await client.keystore.refresh();
      expect(client.keystore.fresh()).to.be.true;
      expect(client.keystore.stale()).to.be.false;
      expect(client.keystore.freshUntil).to.equal(freshUntil);
    });

    it('uses the max-age if Cache-Control is missing', async function () {
      const client = await this.provider.Client.find('client');
      await keystore.generate('EC', 'P-256');

      setResponse(undefined, undefined, {
        'Cache-Control': 'private, max-age=3600',
      });

      const freshUntil = epochTime() + 3600;

      sinon.stub(client.keystore, 'fresh').callsFake(function () {
        this.fresh.restore();
        return false;
      });
      await client.keystore.refresh();
      expect(client.keystore.fresh()).to.be.true;
      expect(client.keystore.stale()).to.be.false;
      expect(client.keystore.freshUntil).to.be.closeTo(freshUntil, 1);
    });

    it('falls back to 1 minute throttle if no caching header is found', async function () {
      const client = await this.provider.Client.find('client');
      await keystore.generate('EC', 'P-256');

      setResponse();

      const freshUntil = epochTime() + 60;

      sinon.stub(client.keystore, 'fresh').callsFake(function () {
        this.fresh.restore();
        return false;
      });
      await client.keystore.refresh();
      expect(client.keystore.fresh()).to.be.true;
      expect(client.keystore.stale()).to.be.false;
      expect(client.keystore.freshUntil).to.be.closeTo(freshUntil, 1);
    });
  });

  describe('refreshing', () => {
    it('when a stale keystore is passed to JWT verification it gets refreshed', async function () {
      setResponse();

      const client = await this.provider.Client.find('client');
      client.keystore.freshUntil = epochTime() - 1;
      await JWT.verify(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
        client.keystore,
      ).then(fail, () => {});
    });

    it('refreshes stale keystores before id_token encryption', async function () {
      setResponse();

      const client = await this.provider.Client.find('client');
      client.keystore.freshUntil = epochTime() - 1;
      expect(client.keystore.stale()).to.be.true;

      const { IdToken } = this.provider;
      const token = new IdToken({ foo: 'bar' }, client);

      await token.sign();
    });
  });
});
