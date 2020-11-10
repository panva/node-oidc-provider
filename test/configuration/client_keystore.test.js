const { strict: assert } = require('assert');

const jose = require('jose');
const moment = require('moment');
const nock = require('nock');
const sinon = require('sinon').createSandbox();
const { expect } = require('chai');
const cloneDeep = require('lodash/cloneDeep');

const runtimeSupport = require('../../lib/helpers/runtime_support');
const mtlsKeys = require('../jwks/jwks.json');
const JWT = require('../../lib/helpers/jwt');
const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const fail = () => { throw new Error('expected promise to be rejected'); };

const endpoint = nock('https://client.example.com/');
const keystore = new jose.JWKS.KeyStore();

const invalidx5c = cloneDeep(mtlsKeys);
invalidx5c.keys[0].x5c = true;

function setResponse(body = keystore.toJWKS(), statusCode = 200, headers = {}) {
  endpoint
    .get('/jwks')
    .reply(statusCode, typeof body === 'string' ? body : JSON.stringify(body), headers);
  assert(!nock.isDone(), 'expected client\'s jwks_uri to be fetched');
}

// NOTE: these tests are to be run sequentially, picking one random won't pass
describe('client keystore refresh', () => {
  afterEach(() => {
    expect(nock.isDone()).to.be.true;
  });

  before(bootstrap(__dirname, { config: 'client_keystore' }));

  before(async function () {
    return i(this.provider).clientAddStatic({
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      jwks_uri: 'https://client.example.com/jwks',
      id_token_signed_response_alg: 'none',
      id_token_encrypted_response_alg: 'ECDH-ES+A128KW',
      id_token_encrypted_response_enc: 'A128CBC-HS256',
    });
  });

  afterEach(sinon.restore);

  it('gets the jwks from the uri (and does only one request concurrently)', async function () {
    await keystore.generate('EC', 'P-256');
    setResponse();

    const client = await this.provider.Client.find('client');
    await Promise.all([
      client.keystore.refresh(),
      client.keystore.refresh(),
    ]);

    expect(client.keystore.get({ kty: 'EC' })).to.be.ok;
  });

  it('fails when private keys are encountered (and does only one request concurrently)', async function () {
    setResponse(keystore.toJWKS(true));

    const client = await this.provider.Client.find('client');
    sinon.stub(client.keystore, 'fresh').returns(false);
    return Promise.all([
      client.keystore.refresh().then(fail, (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.match(/jwks_uri could not be refreshed/);
        expect(err.error_description).to.match(/jwks_uri must not contain private or symmetric keys/);
      }),
      client.keystore.refresh().then(fail, (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.match(/jwks_uri could not be refreshed/);
        expect(err.error_description).to.match(/jwks_uri must not contain private or symmetric keys/);
      }),
    ]);
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
      expect(err.error_description).to.match(/unexpected jwks_uri response status code, expected 200 OK, got 302 Found/);
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
      expect(err.error_description).to.match(/response was not a valid JSON Web Key Set/);
    });
  });

  if (runtimeSupport.KeyObject) {
    it('does x5c validation', async function () {
      setResponse(invalidx5c);

      const client = await this.provider.Client.find('client');
      sinon.stub(client.keystore, 'fresh').returns(false);
      await client.keystore.refresh().then(fail, (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.match(/jwks_uri could not be refreshed/);
        expect(err.error_description).to.match(/must be an array of one or more PKIX certificates when provided/);
      });
    });
  }

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
      this.retries(1);

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
      this.retries(1);

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
    it('keeps the derived keys in keystore', async function () {
      const client = await this.provider.Client.find('client');
      expect(client.keystore.get({ alg: 'HS256' })).to.be.ok;
      setResponse();
      sinon.stub(client.keystore, 'fresh').callsFake(function () {
        this.fresh.restore();
        return false;
      });
      await client.keystore.refresh();
      expect(client.keystore.get({ alg: 'HS256' })).to.be.ok;
    });

    it('when a stale keystore is passed to JWT verification it gets refreshed when verification fails', async function () {
      setResponse();

      const client = await this.provider.Client.find('client');
      client.keystore.freshUntil = epochTime() - 1;
      await JWT.verify(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgA',
        client.keystore,
      ).then(fail, () => {});
    });

    it('refreshes stale keystores before id_token encryption', async function () {
      setResponse();

      const client = await this.provider.Client.find('client');
      client.keystore.freshUntil = epochTime() - 1;
      expect(client.keystore.stale()).to.be.true;

      const { IdToken } = this.provider;
      const token = new IdToken({ foo: 'bar' }, { client, ctx: undefined });

      await token.issue({ use: 'idtoken' });
    });
  });
});
