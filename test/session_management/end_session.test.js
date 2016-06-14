'use strict';

const {
  provider, agent, wrap, getSession
} = require('../test_helper')(__dirname);
const sinon = require('sinon');
const { parse: parseUrl } = require('url');
const { expect } = require('chai');
const JWT = require('../../lib/helpers/jwt');

const route = '/session/end';

provider.setupClient();
provider.setupCerts();

['get', 'post'].forEach((verb) => {
  describe(`[session_management] ${verb} ${route} with session`, function () {
    beforeEach(agent.login);
    afterEach(agent.logout);
    afterEach(function () {
      if (provider.Session.adapter.destroy.restore) {
        provider.Session.adapter.destroy.restore();
      }
    });

    beforeEach(function () {
      return agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid',
        nonce: String(Math.random()),
        response_type: 'id_token',
        redirect_uri: 'https://client.example.com/cb'
      })
      .expect(302)
      .expect((response) => {
        const { query: { id_token: idToken } } = parseUrl(response.headers.location.replace('#', '?'), true);
        this.idToken = idToken;
      });
    });

    it('destroys the session', function () {
      const params = {
        id_token_hint: this.idToken
      };
      const session = getSession(agent);
      const adapter = provider.Session.adapter;
      sinon.spy(adapter, 'destroy');

      return wrap({ agent, route, verb, params })
      .expect(function () {
        expect(adapter.destroy.called).to.be.true;
        expect(adapter.destroy.withArgs(session.id).calledOnce).to.be.true;
      });
    });

    it('passes through the state', function () {
      const params = {
        id_token_hint: this.idToken,
        state: '123'
      };

      return wrap({ agent, route, verb, params })
      .expect('location', /\?state=123$/);
    });

    it('redirects to home if no uri is specified', function () {
      const params = {
        id_token_hint: this.idToken
      };

      return wrap({ agent, route, verb, params })
      .expect('location', '/');
    });

    context('client with postLogoutRedirectUris', function () {
      before(function () {
        provider.Client.clients.client.postLogoutRedirectUris = ['https://client.example.com/logout/cb'];
      });
      after(function () {
        provider.Client.clients.client.postLogoutRedirectUris = [];
      });

      it('allows to redirect there', function () {
        const params = {
          id_token_hint: this.idToken,
          post_logout_redirect_uri: 'https://client.example.com/logout/cb'
        };

        return wrap({ agent, route, verb, params })
        .expect(302)
        .expect('location', 'https://client.example.com/logout/cb');
      });

      it('puts in the post_logout_redirect_uri if its just one defined', function () {
        const params = {
          id_token_hint: this.idToken
        };

        return wrap({ agent, route, verb, params })
        .expect(302)
        .expect('location', 'https://client.example.com/logout/cb');
      });
    });

    it('validates id_token_hint presence', function () {
      const params = {};

      return wrap({ agent, route, verb, params })
      .expect(400)
      .expect(/"error":"invalid_request"/)
      .expect(/"error_description":"missing required parameter\(s\).+id_token_hint/);
    });

    it('validates post_logout_redirect_uri allowed on client', function () {
      const params = {
        id_token_hint: this.idToken,
        post_logout_redirect_uri: 'https://client.example.com/callback/logout'
      };

      return wrap({ agent, route, verb, params })
      .expect(400)
      .expect(/"error":"invalid_request"/)
      .expect(/"error_description":"post_logout_redirect_uri not registered"/);
    });

    it('rejects invalid JWTs', function () {
      const params = {
        id_token_hint: 'not.a.jwt'
      };

      return wrap({ agent, route, verb, params })
      .expect(400)
      .expect(/"error":"invalid_request"/)
      .expect(/"error_description":"could not decode id_token_hint/);
    });

    it('rejects JWTs with unrecognized client', function * () {
      const params = {
        id_token_hint: yield JWT.sign({
          aud: 'nonexistant'
        }, null, 'none')
      };

      return wrap({ agent, route, verb, params })
      .expect(400)
      .expect(/"error":"invalid_request"/)
      .expect(/"error_description":"could not validate id_token_hint \(invalid_client\)/);
    });

    it('rejects JWTs with bad signatures', function * () {
      const params = {
        id_token_hint: yield JWT.sign({
          aud: 'client'
        }, null, 'none')
      };

      return wrap({ agent, route, verb, params })
      .expect(400)
      .expect(/"error":"invalid_request"/)
      .expect(/"error_description":"could not validate id_token_hint/);
    });
  });
});
