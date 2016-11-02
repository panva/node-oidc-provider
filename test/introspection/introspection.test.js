'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/token/introspection';


describe('introspection features', function () {
  before(bootstrap(__dirname)); // agent, provider

  describe('enriched discovery', function () {
    it('shows the url now', function () {
      return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('token_introspection_endpoint').and.matches(/token\/introspect/);
      });
    });
  });

  describe('/token/introspection', function () {
    it('returns the properties for access token [no hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).to.equal('accountId');
        })
        .end(done);
      });
    });

    it('returns the properties for access token [correct hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'access_token'
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).to.equal('accountId');
        })
        .end(done);
      });
    });

    it('returns the properties for access token [wrong hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'refresh_token'
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).to.equal('accountId');
        })
        .end(done);
      });
    });

    it('returns the properties for access token [unrecognized hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'foobar'
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).to.equal('accountId');
        })
        .end(done);
      });
    });

    it('returns the properties for refresh token [no hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        })
        .end(done);
      });
    });

    it('returns the properties for refresh token [correct hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        })
        .end(done);
      });
    });

    it('returns the properties for refresh token [wrong hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        })
        .end(done);
      });
    });

    it('returns the properties for refresh token [unrecognized hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        })
        .end(done);
      });
    });

    it('returns the properties for client credentials token [no hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id');
        })
        .end(done);
      });
    });

    it('returns the properties for client credentials token [correct hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id');
        })
        .end(done);
      });
    });

    it('returns the properties for client credentials token [wrong hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id');
        })
        .end(done);
      });
    });

    it('returns the properties for client credentials token [unrecognized hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id');
        })
        .end(done);
      });
    });

    it('can be called by RS clients and uses the original subject_type', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client-pairwise',
        scope: 'scope',
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client-introspection', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).not.to.equal('accountId');
        })
        .end(done);
      });
    });

    it('returns token-endpoint-like cache headers', function () {
      return this.agent.post(route)
      .auth('client', 'secret')
      .send({})
      .type('form')
      .expect('pragma', 'no-cache')
      .expect('cache-control', 'no-cache, no-store');
    });

    it('validates token param presence', function () {
      return this.agent.post(route)
      .auth('client', 'secret')
      .send({})
      .type('form')
      .expect(400)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter.+\(token\)/);
      });
    });

    it('responds with active=false for total bs', function () {
      return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        token: 'this is not even a token'
      })
      .type('form')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('active', false);
        expect(response.body).to.have.keys('active');
      });
    });

    it('emits on (i.e. auth) error', function () {
      const spy = sinon.spy();
      this.provider.once('introspection.error', spy);

      return this.agent.post(route)
      .auth('invalid', 'auth')
      .send({})
      .type('form')
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      });
    });

    it('ignores unsupported tokens', function* () {
      const ac = new this.provider.AuthorizationCode({ clientId: 'client' });
      return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        token: yield ac.save()
      })
      .type('form')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('active', false);
        expect(response.body).to.have.keys('active');
      });
    });
  });
});
