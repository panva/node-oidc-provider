import { describe, afterEach, before, it } from 'node:test';
import assert from 'node:assert/strict';

import moment from 'moment';
import { createSandbox } from 'sinon';

import * as JWT from '../../lib/helpers/jwt.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import withTimeout from '../with_timeout.js';
import bootstrap, { assertNoPendingInterceptors, mock } from '../test_helper.js';
import initializeClients from '../../lib/helpers/initialize_clients.js';

const sinon = createSandbox();

const keys = [{
  kty: 'EC',
  x: 'kD4NZtqcBOZIxftx1mj2YivhZAIHthDu3NI2QvC0QDY',
  y: 'pwAHxPuyDIQJJeoMvQ7uI7LjOfx8cw8fy37YwzGnxcA',
  crv: 'P-256',
}];

function setResponse(body = {
  keys,
}, statusCode = 200, headers = {}) {
  mock('https://client.example.com')
    .intercept({
      path: '/jwks',
    })
    .reply(statusCode, typeof body === 'string' ? body : JSON.stringify(body), { headers });
}

// NOTE: these tests are to be run sequentially, picking one random won't pass
describe('client keystore refresh', () => {
  const fixture = {};

  afterEach(() => assertNoPendingInterceptors(), { timeout: 3000 });

  before(bootstrap(import.meta.url, fixture, { config: 'client_keystore' }), { timeout: 3000 });

  before(async () => {
    initializeClients.call(fixture.provider, [{
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      jwks_uri: 'https://client.example.com/jwks',
      id_token_signed_response_alg: 'HS256',
      id_token_encrypted_response_alg: 'ECDH-ES+A128KW',
      id_token_encrypted_response_enc: 'A128CBC-HS256',
    }]);
  }, { timeout: 3000 });

  afterEach(() => sinon.restore(), { timeout: 3000 });

  it('gets the jwks from the uri (and does only one request concurrently)', { timeout: 3000 }, async () => {
    setResponse();

    const client = await fixture.provider.Client.find('client');
    await Promise.all([
      client.asymmetricKeyStore.refresh(),
      client.asymmetricKeyStore.refresh(),
    ]);

    assert.notEqual(client.asymmetricKeyStore.selectForSign({ kty: 'EC' }).length, 0);
  });

  it('fails when private keys are encountered (and does only one request concurrently)', { timeout: 3000 }, async () => {
    setResponse({
      keys: [{
        kty: 'EC',
        x: 'vu2xH_Rzev40voYeW5clt1BVjyV1sFld60ZfecW5RbM',
        y: 'bPvB8qkseGy38m8HUQKbsmvtBE_9OEBuUmpJgTRIg28',
        crv: 'P-256',
        d: '9YzpRwRvpKsStP7uPqs0yRvbregkHMYIFy-cG_KJCsY',
      }],
    });

    const client = await fixture.provider.Client.find('client');
    sinon.stub(client.asymmetricKeyStore, 'fresh').returns(false);
    return Promise.all([
      assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'invalid_client_metadata');
        assert.deepEqual(err.error_description, 'client JSON Web Key Set failed to be refreshed');
        assert.equal(err.error_detail, 'invalid_client_metadata');
        ((actual) => { assert.ok(actual instanceof Error); assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'client JSON Web Key Set is invalid'); })(err.cause);
        assert.equal(err.cause.error_detail, 'jwks.keys[0].d must not be provided for EC keys');
        ((actual) => { assert.ok(actual instanceof Error); assert.ok('message' in Object(actual)); assert.equal(actual.message, err.cause.error_detail); })(err.cause.cause);
        return true;
      }),
      assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'invalid_client_metadata');
        assert.deepEqual(err.error_description, 'client JSON Web Key Set failed to be refreshed');
        assert.equal(err.error_detail, 'invalid_client_metadata');
        ((actual) => { assert.ok(actual instanceof Error); assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'client JSON Web Key Set is invalid'); })(err.cause);
        assert.equal(err.cause.error_detail, 'jwks.keys[0].d must not be provided for EC keys');
        ((actual) => { assert.ok(actual instanceof Error); assert.ok('message' in Object(actual)); assert.equal(actual.message, err.cause.error_detail); })(err.cause.cause);
        return true;
      }),
    ]);
  });

  it('fails when private keys are encountered (ML-DSA)', { timeout: 3000 }, async () => {
    setResponse({
      keys: [{
        kty: 'AKP',
        alg: 'ML-DSA-44',
        pub: '<...>',
        priv: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      }],
    });

    const client = await fixture.provider.Client.find('client');
    sinon.stub(client.asymmetricKeyStore, 'fresh').returns(false);
    return Promise.all([
      assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'invalid_client_metadata');
        assert.deepEqual(err.error_description, 'client JSON Web Key Set failed to be refreshed');
        assert.equal(err.cause.error_detail, 'jwks.keys[0].priv must not be provided for AKP keys');
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, err.cause.error_detail); })(err.cause.cause);
        return true;
      }),
      assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'invalid_client_metadata');
        assert.deepEqual(err.error_description, 'client JSON Web Key Set failed to be refreshed');
        assert.equal(err.cause.error_detail, 'jwks.keys[0].priv must not be provided for AKP keys');
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, err.cause.error_detail); })(err.cause.cause);
        return true;
      }),
    ]);
  });

  it('adds new keys', { timeout: 3000 }, async () => {
    const client = await fixture.provider.Client.find('client');
    keys.push({
      kty: 'EC',
      x: 'pPrd-y2inidf7iiYmB_ymaTWZrBresjbgmnjLzIOiBY',
      y: 'Wkxz6RSvg9xEvDLppPJ0Bi7psTF974mXSlpuf_x120c',
      crv: 'P-256',
    });
    setResponse();

    sinon.stub(client.asymmetricKeyStore, 'fresh').returns(false);
    await client.asymmetricKeyStore.refresh();
    assert.equal(client.asymmetricKeyStore.selectForSign({ kty: 'EC' }).length, 2);
  });

  it('removes not found keys', { timeout: 3000 }, async () => {
    setResponse({ keys: [] });

    const client = await fixture.provider.Client.find('client');
    sinon.stub(client.asymmetricKeyStore, 'fresh').returns(false);
    await client.asymmetricKeyStore.refresh();

    assert.equal(client.asymmetricKeyStore.selectForSign({ kty: 'EC' }).length, 0);
  });

  it('only accepts 200s', { timeout: 3000 }, async () => {
    setResponse({ keys: [] }, 201);

    const client = await fixture.provider.Client.find('client');
    sinon.stub(client.asymmetricKeyStore, 'fresh').returns(false);
    return assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, 'invalid_client_metadata');
      assert.deepEqual(err.error_description, 'client JSON Web Key Set failed to be refreshed');
      return true;
    });
  });

  it('only accepts parseable json', { timeout: 3000 }, async () => {
    setResponse('not json');

    const client = await fixture.provider.Client.find('client');
    sinon.stub(client.asymmetricKeyStore, 'fresh').returns(false);
    return assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, 'invalid_client_metadata');
      assert.deepEqual(err.error_description, 'client JSON Web Key Set failed to be refreshed');
      return true;
    });
  });

  it('only accepts keys as array', { timeout: 3000 }, async () => {
    setResponse({ keys: {} });

    const client = await fixture.provider.Client.find('client');
    sinon.stub(client.asymmetricKeyStore, 'fresh').returns(false);
    return assert.rejects(client.asymmetricKeyStore.refresh(), (err) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, 'invalid_client_metadata');
      assert.deepEqual(err.error_description, 'client JSON Web Key Set failed to be refreshed');
      return true;
    });
  });

  describe('caching', () => {
    const fixture1 = Object.create(fixture);

    it('uses expires caching header to determine stale states', { timeout: 3000 }, async () => {
      const client = await fixture1.provider.Client.find('client');
      const until = moment().add(2, 'hours').toDate();

      setResponse(undefined, undefined, {
        Expires: until.toUTCString(),
      });

      const freshUntil = epochTime(until);

      sinon.stub(client.asymmetricKeyStore, 'fresh').callsFake(function () {
        this.fresh.restore();
        return false;
      });
      await client.asymmetricKeyStore.refresh();
      assert.equal(client.asymmetricKeyStore.fresh(), true);
      assert.equal(client.asymmetricKeyStore.stale(), false);
      assert.equal(client.asymmetricKeyStore.freshUntil, freshUntil);
    });

    it('ignores the cache-control one when expires is provided', { timeout: 3000 }, async () => {
      const client = await fixture1.provider.Client.find('client');
      const until = moment().add(2, 'hours').toDate();

      setResponse(undefined, undefined, {
        Expires: until.toUTCString(),
        'Cache-Control': 'private, max-age: 3600',
      });

      const freshUntil = epochTime(until);

      sinon.stub(client.asymmetricKeyStore, 'fresh').callsFake(function () {
        this.fresh.restore();
        return false;
      });
      await client.asymmetricKeyStore.refresh();
      assert.equal(client.asymmetricKeyStore.fresh(), true);
      assert.equal(client.asymmetricKeyStore.stale(), false);
      assert.equal(client.asymmetricKeyStore.freshUntil, freshUntil);
    });

    it('uses the max-age if Cache-Control is missing', { timeout: 7000 }, async () => {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
          await withTimeout(async () => {
            const client = await fixture1.provider.Client.find('client');

            setResponse(undefined, undefined, {
              'Cache-Control': 'private, max-age=3600',
            });

            const freshUntil = epochTime() + 3600;

            sinon.stub(client.asymmetricKeyStore, 'fresh').callsFake(function () {
              this.fresh.restore();
              return false;
            });
            await client.asymmetricKeyStore.refresh();
            assert.equal(client.asymmetricKeyStore.fresh(), true);
            assert.equal(client.asymmetricKeyStore.stale(), false);
            assert.equal(typeof client.asymmetricKeyStore.freshUntil, 'number');
            assert.ok(Math.abs(client.asymmetricKeyStore.freshUntil - freshUntil) <= 1);
          }, 3000);
          return;
        } catch (error) {
          if (attempt === 1) throw error;
        } finally {
          try {
            assertNoPendingInterceptors();
          } finally {
            sinon.restore();
          }
        }
      }
    });

    it('falls back to 1 minute throttle if no caching header is found', { timeout: 7000 }, async () => {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
          await withTimeout(async () => {
            const client = await fixture1.provider.Client.find('client');

            setResponse();

            const freshUntil = epochTime() + 60;

            sinon.stub(client.asymmetricKeyStore, 'fresh').callsFake(function () {
              this.fresh.restore();
              return false;
            });
            await client.asymmetricKeyStore.refresh();
            assert.equal(client.asymmetricKeyStore.fresh(), true);
            assert.equal(client.asymmetricKeyStore.stale(), false);
            assert.equal(typeof client.asymmetricKeyStore.freshUntil, 'number');
            assert.ok(Math.abs(client.asymmetricKeyStore.freshUntil - freshUntil) <= 1);
          }, 3000);
          return;
        } catch (error) {
          if (attempt === 1) throw error;
        } finally {
          try {
            assertNoPendingInterceptors();
          } finally {
            sinon.restore();
          }
        }
      }
    });
  });

  describe('refreshing', () => {
    const fixture2 = Object.create(fixture);

    it('when a stale keystore is passed to JWT verification it gets refreshed when verification fails', { timeout: 3000 }, async () => {
      setResponse();

      const client = await fixture2.provider.Client.find('client');
      client.asymmetricKeyStore.freshUntil = epochTime() - 1;
      return assert.rejects(JWT.verify(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgA',
        client.asymmetricKeyStore,
      ));
    });

    it('refreshes stale keystores before id_token encryption', { timeout: 3000 }, async () => {
      setResponse();

      const client = await fixture2.provider.Client.find('client');
      client.asymmetricKeyStore.freshUntil = epochTime() - 1;
      assert.equal(client.asymmetricKeyStore.stale(), true);

      const { IdToken } = fixture2.provider;
      const token = new IdToken({ foo: 'bar' }, { client, ctx: undefined });

      await token.issue({ use: 'idtoken' });
    });

    it('reports an invalid id_token signing algorithm', { timeout: 3000 }, async () => {
      const client = await fixture2.provider.Client.find('client');
      const original = client.idTokenSignedResponseAlg;
      client.idTokenSignedResponseAlg = undefined;

      try {
        const { IdToken } = fixture2.provider;
        const token = new IdToken({ foo: 'bar' }, { client, ctx: undefined });

        await assert.rejects(token.issue({ use: 'idtoken' }), (err) => {
          ((actual) => { assert.ok(actual instanceof Error); assert.ok('message' in Object(actual)); assert.equal(actual.message, 'idtoken signing algorithm must be a string'); })(err);
          assert.equal(err.cause, client);
          return true;
        });
      } finally {
        client.idTokenSignedResponseAlg = original;
      }
    });
  });
});
