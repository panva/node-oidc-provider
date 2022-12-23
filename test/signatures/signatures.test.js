import { parse as parseLocation } from 'node:url';

import { generateKeyPair } from 'jose';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';
import { decode } from '../../lib/helpers/jwt.js';
import epochTime from '../../lib/helpers/epoch_time.js';

describe('signatures', () => {
  before(bootstrap(import.meta.url));

  describe('when id_token_signed_response_alg=HS256', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });
    beforeEach(async function () {
      const ac = new this.provider.AuthorizationCode({
        accountId: this.loggedInAccountId,
        acr: i(this.provider).configuration('acrValues[0]'),
        authTime: epochTime(),
        clientId: 'client-sig-HS256',
        grantId: this.getGrantId('client-sig-HS256'),
        redirectUri: 'https://client.example.com/cb',
        scope: 'openid',
      });

      return this.agent.post('/token')
        .auth('client-sig-HS256', 'secret')
        .type('form')
        .send({
          redirect_uri: 'https://client.example.com/cb',
          grant_type: 'authorization_code',
          code: await ac.save(),
        })
        .expect(200)
        .expect((response) => {
          this.idToken = response.body.id_token;
        });
    });

    it('issues an HS256 signed id_token', function () {
      const components = this.idToken.split('.');
      expect(components).to.have.lengthOf(3);
      expect(components[2]).not.to.equal('');
      expect(decode(this.idToken)).to.have.nested.property('header.alg', 'HS256');
    });

    it('the HS256 signed token can be used as id_token_hint', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'none',
        id_token_hint: this.idToken,
      });
      auth.client_id = 'client-sig-HS256';

      return this.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
    });
  });

  describe('token hashes in id_token', () => {
    before(async function () {
      this.client = await this.provider.Client.find('client');
    });

    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    after(function () {
      this.client.idTokenSignedResponseAlg = 'RS256';
    });

    it('responds with a access_token and code (half of sha512 Ed25519)', function () {
      this.client.idTokenSignedResponseAlg = 'EdDSA';
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return this.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          expect(payload).to.contain.keys('at_hash', 'c_hash');
          expect(payload.at_hash).to.have.lengthOf(43);
        });
    });

    it('responds with a access_token and code (half of sha512)', function () {
      this.client.idTokenSignedResponseAlg = 'RS512';
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return this.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          expect(payload).to.contain.keys('at_hash', 'c_hash');
          expect(payload.at_hash).to.have.lengthOf(43);
        });
    });

    it('responds with a access_token and code (half of sha384)', function () {
      this.client.idTokenSignedResponseAlg = 'RS384';
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return this.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          expect(payload).to.contain.keys('at_hash', 'c_hash');
          expect(payload.at_hash).to.have.lengthOf(32);
        });
    });

    it('responds with a access_token and code (half of sha256)', function () {
      this.client.idTokenSignedResponseAlg = 'RS256';
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return this.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          expect(payload).to.contain.keys('at_hash', 'c_hash');
          expect(payload.at_hash).to.have.lengthOf(22);
        });
    });

    it('responds with a access_token and code (half of shake256(m, 114) Ed448)', async function () {
      this.client.idTokenSignedResponseAlg = 'EdDSA';
      i(this.provider).keystore.clear();
      i(this.provider).keystore.add((await generateKeyPair('EdDSA', { crv: 'Ed448' })).privateKey.export({ format: 'jwk' }));
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return this.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          expect(payload).to.contain.keys('at_hash', 'c_hash');
          expect(payload.at_hash).to.have.lengthOf(76);
        });
    });
  });
});
