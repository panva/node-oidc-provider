'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/token/revocation';


describe('revocation features', () => {
  const { agent, provider } = bootstrap(__dirname);
  const AuthorizationCode = provider.AuthorizationCode;
  const AccessToken = provider.AccessToken;
  const ClientCredentials = provider.ClientCredentials;
  const RefreshToken = provider.RefreshToken;

  provider.setupClient();


  describe('enriched discovery', () => {
    it('shows the url now', () => {
      return agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('token_revocation_endpoint').and.matches(/token\/revocation/);
      });
    });
  });

  describe(route, () => {
    it('revokes access token [no hint]', (done) => {
      const at = new AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes access token [correct hint]', (done) => {
      const at = new AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes access token [wrong hint]', (done) => {
      const at = new AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes access token [unrecognized hint]', (done) => {
      const at = new AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(AccessToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      at.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('propagates exceptions on find', (done) => {
      const at = new AccessToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      sinon.stub(AccessToken, 'find').returns(Promise.reject(new Error('Error')));

      at.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          AccessToken.find.restore();
        })
        .expect(500)
        .expect((response) => {
          expect(response.body.error).to.eql('server_error');
        })
        .end(done);
      });
    });

    it('revokes refresh token [no hint]', (done) => {
      const rt = new RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes refresh token [correct hint]', (done) => {
      const rt = new RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes refresh token [wrong hint]', (done) => {
      const rt = new RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes refresh token [unrecognized hint]', (done) => {
      const rt = new RefreshToken({
        accountId: 'accountId',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(RefreshToken.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [no hint]', (done) => {
      const rt = new ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [correct hint]', (done) => {
      const rt = new ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [wrong hint]', (done) => {
      const rt = new ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token [unrecognized hint]', (done) => {
      const rt = new ClientCredentials({
        clientId: 'client'
      });

      const stub = sinon.stub(ClientCredentials.prototype, 'destroy', () => {
        return Promise.resolve();
      });

      rt.save().then((token) => {
        agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('validates token param presence', () => {
      return agent.post(route)
      .auth('client', 'secret')
      .send({})
      .type('form')
      .expect(400)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter.+\(token\)/);
      });
    });

    it('rejects completely wrong tokens with the expected OK response', () => {
      return agent.post(route)
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
      const ac = new AuthorizationCode({ clientId: 'client' });
      return agent.post(route)
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

    it('does not revoke tokens of other clients', (done) => {
      const at = new AccessToken({
        accountId: 'accountId',
        clientId: 'client2',
        scope: 'scope',
      });

      at.save().then((token) => {
        agent.post(route)
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

    it('emits on (i.e. auth) error', () => {
      const spy = sinon.spy();
      provider.once('revocation.error', spy);

      return agent.post(route)
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
