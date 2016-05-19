'use strict';

const { agent, provider } = require('../test_helper')(__dirname);
const sinon = require('sinon');
const { expect } = require('chai');
const { encode: base64url } = require('base64url');
const { stringify: qs } = require('querystring');
const route = '/token/revocation';
const j = JSON.stringify;

provider.setupClient();
provider.setupCerts();

describe('revocation features', function () {
  describe('enriched discovery', function () {
    it('shows the url now', function () {
      return agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect(function (response) {
        expect(response.body).to.have.property('token_revocation_endpoint').and.matches(/token\/revocation/);
      });
    });
  });

  describe('/token/revocation', function () {
    it('revokes access token', function (done) {
      const at = new provider.AccessToken({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      const stub = sinon.stub(provider.AccessToken.prototype, 'destroy', function () {
        return Promise.resolve();
      });

      at.toToken().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(function () {
          expect(stub.calledOnce).to.be.true;
          provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('ignores find exceptions on AccessToken', function (done) {
      const at = new provider.AccessToken({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      sinon.stub(provider.AccessToken, 'find').throws();

      at.toToken().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(function () {
          provider.AccessToken.find.restore();
        })
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes refresh token', function (done) {
      const rt = new provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      const stub = sinon.stub(provider.RefreshToken.prototype, 'destroy', function () {
        return Promise.resolve();
      });

      rt.toToken().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(function () {
          expect(stub.calledOnce).to.be.true;
          provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('ignores find exceptions on RefreshToken', function (done) {
      const at = new provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      sinon.stub(provider.RefreshToken, 'find').throws();

      at.toToken().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(function () {
          provider.RefreshToken.find.restore();
        })
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('revokes client credentials token', function (done) {
      const rt = new provider.ClientCredentials({
        clientId: 'clientId'
      });

      const stub = sinon.stub(provider.ClientCredentials.prototype, 'destroy', function () {
        return Promise.resolve();
      });

      rt.toToken().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(function () {
          expect(stub.calledOnce).to.be.true;
          provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('ignores find exceptions on ClientCredentials', function (done) {
      const at = new provider.ClientCredentials({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      sinon.stub(provider.ClientCredentials, 'find').throws();

      at.toToken().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(function () {
          provider.ClientCredentials.find.restore();
        })
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('ignores decode exceptions', function (done) {
      const at = new provider.ClientCredentials({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      sinon.stub(provider.OAuthToken, 'decode').throws();

      at.toToken().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(function () {
          provider.OAuthToken.decode.restore();
        })
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.eql({});
        })
        .end(done);
      });
    });

    it('validates token param presence', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({}))
      .expect(400)
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter.+\(token\)/);
      });
    });

    it('even bad tokens of valid format still get valid response', function () {
      const fields = {
        kind: 'ClientCredentials',
        exp: 1,
        iat: 2,
        iss: 'me',
        jti: 'id'
      };
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        token: `${base64url(j(fields))}.`
      }))
      .expect(200)
      .expect(function (response) {
        expect(response.body).to.eql({});
      });
    });

    it('rejects unssuported tokens', function () {
      const fields = {
        kind: 'whateveratthisstage',
        exp: 1,
        iat: 2,
        iss: 'me',
        jti: 'id'
      };
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        token: `${base64url(j(fields))}.`
      }))
      .expect(400)
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'unsupported_token_type');
      });
    });

    it('emits on (i.e. auth) error', function () {
      const spy = sinon.spy();
      provider.once('revocation.error', spy);

      return agent.post(route)
      .auth('invalid', 'auth')
      .send(qs({}))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      });
    });
  });
});
