const base64url = require('base64url');
const sinon = require('sinon');
const bootstrap = require('../test_helper');
const { parse: parseUrl } = require('url');
const { expect } = require('chai');

function errorDetail(spy) {
  return spy.args[0][0].error_detail;
}

describe('OAuth 2.0 Mix-Up Mitigation', function () {
  before(bootstrap(__dirname)); // provider, agent, this.AuthorizationRequest, TestAdapter

  describe('authorization', function () {
    before(function () { return this.login(); });

    it('returns iss and client_id on error', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'profile',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state', 'iss', 'client_id']))
        .expect((response) => {
          const { query: { iss, client_id } } = parseUrl(response.headers.location, true);

          expect(iss).to.equal(this.provider.issuer);
          expect(client_id).to.equal('client');
        });
    });

    it('returns iss and client_id on non id_token responses (1/2)', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['code', 'state', 'iss', 'client_id']))
        .expect((response) => {
          const { query: { iss, client_id } } = parseUrl(response.headers.location, true);

          expect(iss).to.equal(this.provider.issuer);
          expect(client_id).to.equal('client');
        });
    });

    it('returns iss and client_id on non id_token responses (2/2)', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state', 'iss', 'client_id', 'access_token', 'token_type', 'expires_in']))
        .expect((response) => {
          const { query: { iss, client_id } } = parseUrl(response.headers.location, true);

          expect(iss).to.equal(this.provider.issuer);
          expect(client_id).to.equal('client');
        });
    });

    it('omits iss and client_id on id_token including responses 1/2', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token',
        scope: 'openid',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state']));
    });

    it('omits iss and client_id on id_token including responses 1/2', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token',
        scope: 'openid',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state', 'code']));
    });

    it('puts the state to authorization code', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        state: 'foobar',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = code.substring(0, 48);
          const stored = this.TestAdapter.for('AuthorizationCode').syncFind(jti);
          const payload = JSON.parse(base64url.decode(stored.payload));

          expect(payload).to.have.property('state', 'foobar');
        });
    });
  });

  describe('token grant_type=authorization_code', function () {
    it('passes when the state matches', async function () {
      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        state: 'foobar',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          state: 'foobar',
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb'
        })
        .expect(200);
    });

    it('passes when no state is present on the auth code', async function () {
      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        // state: 'foobar',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          state: 'foobar',
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb'
        })
        .expect(200);
    });

    it('fails when state mismatches', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        state: 'foobar',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          state: 'barbaz',
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb'
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('state mismatch');
        });
    });
  });
});
