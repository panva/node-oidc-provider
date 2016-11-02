'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/token/revocation';


describe('revocation features', function () {
  before(bootstrap(__dirname)); // this.agent, provider

  describe('enriched discovery', function () {
    it('shows the url now', function () {
      return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('token_revocation_endpoint').and.matches(/token\/revocation/);
      });
    });
  });

  describe(route, function () {
    it('revokes access token [no hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes access token [correct hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes access token [wrong hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes access token [unrecognized hint]', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('propagates exceptions on find', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      sinon.stub(this.provider.AccessToken, 'find').returns(Promise.reject(new Error('Error')));

      at.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          this.provider.AccessToken.find.restore();
        })
        .expect(500)
        .expect((response) => {
          expect(response.body.error).to.eql('server_error');
        })
        .end(done);
      });
    });

    it('revokes refresh token [no hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes refresh token [correct hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes refresh token [wrong hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes refresh token [unrecognized hint]', function (done) {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [no hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [correct hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [wrong hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [unrecognized hint]', function (done) {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
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

    it('rejects completely wrong tokens with the expected OK response', function () {
      return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        token: 'dsahjdasdsa'
      })
      .type('form')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.eql({});
      });
    });

    it('rejects unsupported tokens', function* () {
      const ac = new this.provider.AuthorizationCode({ clientId: 'client' });
      return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        token: yield ac.save()
      })
      .type('form')
      .expect(400)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'unsupported_token_type');
      });
    });

    it('does not revoke tokens of other clients', function (done) {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        clientId: 'client2',
        scope: 'scope',
      });

      at.save().then((token) => {
        this.agent.post(route)
          .auth('client', 'secret')
          .send({ token })
          .type('form')
          .expect(400)
          .expect((response) => {
            expect(response.body).to.eql({
              error: 'invalid_request',
              error_description: 'this token does not belong to you'
            });
          })
          .end(done);
      });
    });

    it('emits on (i.e. auth) error', function () {
      const spy = sinon.spy();
      this.provider.once('revocation.error', spy);

      return this.agent.post(route)
      .auth('invalid', 'auth')
      .send({})
      .type('form')
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      });
    });
  });
});
