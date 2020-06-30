const { parse: parseLocation } = require('url');

const { expect } = require('chai');
const base64url = require('base64url');

const nanoid = require('../../lib/helpers/nanoid');
const bootstrap = require('../test_helper');
const { decode } = require('../../lib/helpers/jwt');
const epochTime = require('../../lib/helpers/epoch_time');
const { EdDSA, shake256 } = require('../../lib/helpers/runtime_support');

const { formats: { AccessToken: FORMAT } } = global.TEST_CONFIGURATION_DEFAULTS;

describe('signatures', () => {
  before(bootstrap(__dirname));

  describe('token hashes in id_token', () => {
    before(async function () {
      this.client = await this.provider.Client.find('client');
    });

    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    after(function () {
      this.client.idTokenSignedResponseAlg = 'RS256';
    });

    if (EdDSA) {
      it('responds with a access_token and code (half of sha512 Ed25519)', function () {
        this.client.idTokenSignedResponseAlg = 'EdDSA';
        const auth = new this.AuthorizationRequest({
          response_type: 'code id_token token',
          scope: 'openid',
        });

        return this.wrap({ auth, verb: 'get', route: '/auth' })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decode(id_token);
            expect(payload).to.contain.keys('at_hash', 'c_hash');
            expect(payload.at_hash).to.have.lengthOf(43);
          });
      });

      if (shake256) {
        it('responds with a access_token and code (half of shake256(m, 114) Ed448)', async function () {
          this.client.idTokenSignedResponseAlg = 'EdDSA';
          const key = i(this.provider).keystore.get({ alg: 'EdDSA' });
          i(this.provider).keystore.remove(key);
          await i(this.provider).keystore.generate('OKP', 'Ed448');
          await i(this.provider).keystore.generate('OKP', 'Ed25519');
          const auth = new this.AuthorizationRequest({
            response_type: 'code id_token token',
            scope: 'openid',
          });

          return this.wrap({ auth, verb: 'get', route: '/auth' })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validateClientLocation)
            .expect((response) => {
              const { query: { id_token } } = parseLocation(response.headers.location, true);
              const { payload } = decode(id_token);
              expect(payload).to.contain.keys('at_hash', 'c_hash');
              expect(payload.at_hash).to.have.lengthOf(76);
            });
        });
      }
    }

    it('responds with a access_token and code (half of sha512)', function () {
      this.client.idTokenSignedResponseAlg = 'RS512';
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return this.wrap({ auth, verb: 'get', route: '/auth' })
        .expect(302)
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
        .expect(302)
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
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decode(id_token);
          expect(payload).to.contain.keys('at_hash', 'c_hash');
          expect(payload.at_hash).to.have.lengthOf(22);
        });
    });
  });

  describe('when id_token_signed_response_alg=none', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });
    beforeEach(async function () {
      const ac = new this.provider.AuthorizationCode({
        accountId: 'accountIdentity',
        acr: i(this.provider).configuration('acrValues[0]'),
        authTime: epochTime(),
        clientId: 'client-sig-none',
        grantId: nanoid(),
        redirectUri: 'https://client.example.com/cb',
        scope: 'openid',
      });

      return this.agent.post('/token')
        .auth('client-sig-none', 'secret')
        .type('form')
        .send({
          redirect_uri: 'https://client.example.com/cb',
          grant_type: 'authorization_code',
          code: await ac.save(),
        })
        .expect(200)
        .expect((response) => {
          this.idToken = response.body.id_token;
          this.accessToken = response.body.access_token;
        });
    });

    it('issues an unsigned id_token', function () {
      const components = this.idToken.split('.');
      expect(components).to.have.lengthOf(3);
      expect(components[2]).to.equal('');
      expect(decode(this.idToken)).to.have.nested.property('header.alg', 'none');
    });

    if (FORMAT === 'jwt') {
      it('but the access token remains signed with RS256', function () {
        const components = this.accessToken.split('.');
        expect(components).to.have.lengthOf(3);
        expect(components[2]).not.to.equal('');
        expect(decode(this.accessToken)).to.have.nested.property('header.alg', 'RS256');
      });
    }

    it('the unsigned token can be used as id_token_hint', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'none',
        id_token_hint: this.idToken,
      });
      auth.client_id = 'client-sig-none';

      return this.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('login_required'))
        .expect(auth.validateErrorDescription('id_token_hint and authenticated subject do not match'));
    });

    it('still validates the tokens payload', function () {
      const parts = this.idToken.split('.');
      const payload = JSON.parse(base64url.decode(parts[1]));
      payload.iss = 'foobar';
      parts[1] = base64url(JSON.stringify(payload));
      this.idToken = parts.join('.');
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'none',
        id_token_hint: this.idToken,
      });
      auth.client_id = 'client-sig-none';

      return this.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription(/^could not validate id_token_hint \(jwt issuer invalid/));
    });
  });

  describe('when id_token_signed_response_alg=HS256', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });
    beforeEach(async function () {
      const ac = new this.provider.AuthorizationCode({
        accountId: 'accountIdentity',
        acr: i(this.provider).configuration('acrValues[0]'),
        authTime: epochTime(),
        clientId: 'client-sig-HS256',
        grantId: nanoid(),
        redirectUri: 'https://client.example.com/cb',
        scope: 'openid',
      });

      return this.agent.post('/token')
        .auth('client-sig-HS256', 'atleast32byteslongforHS256mmkay?')
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
        .expect(302)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('login_required'))
        .expect(auth.validateErrorDescription('id_token_hint and authenticated subject do not match'));
    });
  });
});
