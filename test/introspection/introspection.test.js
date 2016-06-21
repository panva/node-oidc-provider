'use strict';

const { agent, provider } = require('../test_helper')(__dirname);
const sinon = require('sinon');
const { expect } = require('chai');
const { encode: base64url } = require('base64url');
const { stringify: qs } = require('querystring');
const route = '/token/introspection';
const j = JSON.stringify;

provider.setupClient();
provider.setupCerts();

describe('introspection features', function () {
  describe('enriched discovery', function () {
    it('shows the url now', function () {
      return agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect(function (response) {
        expect(response.body).to.have.property('token_introspection_endpoint').and.matches(/token\/introspect/);
      });
    });
  });

  describe('/token/introspection', function () {
    it('returns the properties for access token', function (done) {
      const at = new provider.AccessToken({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      at.save().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        })
        .end(done);
      });
    });

    it('returns the properties for refresh token', function (done) {
      const rt = new provider.RefreshToken({
        accountId: 'accountId',
        clientId: 'clientId',
        scope: 'scope',
      });

      rt.save().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        })
        .end(done);
      });
    });

    it('returns the properties for client credentials token', function (done) {
      const rt = new provider.ClientCredentials({
        clientId: 'clientId'
      });

      rt.save().then(function (token) {
        agent.post(route)
        .auth('client', 'secret')
        .send(qs({
          token
        }))
        .expect(200)
        .expect(function (response) {
          expect(response.body).to.contain.keys('client_id');
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

    it('responds with active=false for total bs', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        token: 'this is not even a token'
      }))
      .expect(200)
      .expect(function (response) {
        expect(response.body).to.have.property('active', false);
        expect(response.body).to.have.keys('active');
      });
    });

    it('responds with atleast what it can decode', function () {
      const fields = {
        kind: 'whateveratthisstage',
        exp: 1,
        iat: 2,
        iss: 'me',
        jti: 'id',
        scope: 'openid'
      };
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        token: `${base64url(j(fields))}.`
      }))
      .expect(200)
      .expect(function (response) {
        delete fields.kind;
        expect(response.body).to.contain.all.keys(Object.keys(fields));
      });
    });

    it('emits on (i.e. auth) error', function () {
      const spy = sinon.spy();
      provider.once('introspection.error', spy);

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
