import { describe, before, after, beforeEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseLocation } from 'node:url';


import bootstrap from '../test_helper.js';
import { decode } from '../../lib/helpers/jwt.js';
import epochTime from '../../lib/helpers/epoch_time.js';

describe('signatures', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('when id_token_signed_response_alg=HS256', () => {
    const fixture1 = Object.create(fixture);

    before(() => fixture1.login(), { timeout: 3000 });
    after(() => fixture1.logout(), { timeout: 3000 });
    beforeEach(async () => {
      const ac = new fixture1.provider.AuthorizationCode({
        accountId: fixture1.loggedInAccountId,
        acr: i(fixture1.provider).configuration.acrValues[0],
        authTime: epochTime(),
        clientId: 'client-sig-HS256',
        grantId: fixture1.getGrantId('client-sig-HS256'),
        redirectUri: 'https://client.example.com/cb',
        scope: 'openid',
      });

      return fixture1.agent.post('/token')
        .auth('client-sig-HS256', 'secret')
        .type('form')
        .send({
          redirect_uri: 'https://client.example.com/cb',
          grant_type: 'authorization_code',
          code: await ac.save(),
        })
        .expect(200)
        .expect((response) => {
          fixture1.idToken = response.body.id_token;
        });
    }, { timeout: 3000 });

    it('issues an HS256 signed id_token', { timeout: 3000 }, () => {
      const components = fixture1.idToken.split('.');
      assert.equal(components.length, 3);
      assert.notEqual(components[2], '');
      ((actual) => { assert.ok("alg" in Object(actual.header)); assert.equal(actual.header.alg, 'HS256'); })(decode(fixture1.idToken));
    });

    it('the HS256 signed token can be used as id_token_hint', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'none',
        id_token_hint: fixture1.idToken,
      });
      auth.client_id = 'client-sig-HS256';

      return fixture1.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
    });
  });

  describe('token hashes in id_token', () => {
    const fixture2 = Object.create(fixture);

    before(async () => {
      fixture2.client = await fixture2.provider.Client.find('client');
    }, { timeout: 3000 });

    before(() => fixture2.login(), { timeout: 3000 });
    after(() => fixture2.logout(), { timeout: 3000 });

    after(() => {
      fixture2.client.idTokenSignedResponseAlg = 'RS256';
    }, { timeout: 3000 });

    it('responds with a access_token and code (half of sha512 for EdDSA and Ed25519)', { timeout: 3000 }, async () => {
      for (const alg of ['Ed25519', 'EdDSA']) {
        fixture2.client.idTokenSignedResponseAlg = alg;
        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code id_token token',
          scope: 'openid',
        });

        await fixture2.wrap({ auth, verb: 'get', route: '/auth' })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decode(id_token);
            assert.ok(['at_hash', 'c_hash'].every((key) => Object.keys(payload).includes(key)));
            assert.equal(payload.at_hash.length, 43);
          });
      }
    });

    for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
      it(`responds with a access_token and code (half of shake256(m, 64) for ${alg})`, { timeout: 3000 }, async (t) => {
        if (SubtleCrypto.supports?.('generateKey', alg) !== true) {
          return t.skip();
        }
        fixture2.client.idTokenSignedResponseAlg = alg;
        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code id_token token',
          scope: 'openid',
        });

        await fixture2.wrap({ auth, verb: 'get', route: '/auth' })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decode(id_token);
            assert.ok(['at_hash', 'c_hash'].every((key) => Object.keys(payload).includes(key)));
            assert.equal(payload.at_hash.length, 43);
          });
      });
    }

    it('responds with a access_token and code (half of sha512)', { timeout: 3000 }, () => {
      fixture2.client.idTokenSignedResponseAlg = 'RS512';
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return fixture2.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          assert.ok(['at_hash', 'c_hash'].every((key) => Object.keys(payload).includes(key)));
          assert.equal(payload.at_hash.length, 43);
        });
    });

    it('responds with a access_token and code (half of sha384)', { timeout: 3000 }, () => {
      fixture2.client.idTokenSignedResponseAlg = 'RS384';
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return fixture2.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          assert.ok(['at_hash', 'c_hash'].every((key) => Object.keys(payload).includes(key)));
          assert.equal(payload.at_hash.length, 32);
        });
    });

    it('responds with a access_token and code (half of sha256)', { timeout: 3000 }, () => {
      fixture2.client.idTokenSignedResponseAlg = 'RS256';
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return fixture2.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          assert.ok(['at_hash', 'c_hash'].every((key) => Object.keys(payload).includes(key)));
          assert.equal(payload.at_hash.length, 22);
        });
    });
  });
});
