'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { parse: parseUrl } = require('url');
const { expect } = require('chai');
const JWT = require('../../lib/helpers/jwt');

const route = '/session/end';

describe('[session_management]', function () {
  before(bootstrap(__dirname)); // this.provider, agent, getSession, getSessionId, this.TestAdapter

  beforeEach(function () { return this.login(); });
  afterEach(function () { return this.logout(); });
  afterEach(function () {
    if (this.TestAdapter.for('Session').destroy.restore) {
      this.TestAdapter.for('Session').destroy.restore();
    }
  });

  beforeEach(function () {
    return this.agent.get('/auth')
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

  describe('GET end_session', function () {
    context('client with postLogoutRedirectUris', function () {
      before(function* () {
        (yield this.provider.Client.find('client')).postLogoutRedirectUris = ['https://client.example.com/logout/cb'];
      });
      after(function* () {
        (yield this.provider.Client.find('client')).postLogoutRedirectUris = [];
      });

      it('allows to redirect there', function () {
        const params = {
          id_token_hint: this.idToken,
          post_logout_redirect_uri: 'https://client.example.com/logout/cb'
        };

        return this.agent.get(route)
          .query(params)
          .expect(200)
          .expect(() => {
            const { logout: { postLogoutRedirectUri } } = this.getSession();
            expect(postLogoutRedirectUri).to.equal('https://client.example.com/logout/cb');
          });
      });

      it('can omit the post_logout_redirect_uri and uses the provider one', function () {
        const params = { id_token_hint: this.idToken };

        return this.agent.get(route)
          .query(params)
          .expect(200)
          .expect(() => {
            const { logout: { postLogoutRedirectUri } } = this.getSession();
            expect(postLogoutRedirectUri).to.equal('/?loggedOut=true');
          });
      });
    });

    it('without id_token_hint ignores the provided post_logout_redirect_uri', function () {
      const params = { post_logout_redirect_uri: 'http://rp.example.com/logout/cb' };

      return this.agent.get(route)
        .query(params)
        .expect(200)
        .expect(() => {
          const { logout: { postLogoutRedirectUri } } = this.getSession();
          expect(postLogoutRedirectUri).to.equal('/?loggedOut=true');
        });
    });

    it('validates post_logout_redirect_uri allowed on client', function () {
      const params = {
        id_token_hint: this.idToken,
        post_logout_redirect_uri: 'https://client.example.com/callback/logout'
      };

      return this.agent.get(route)
        .query(params)
        .expect(400)
        .expect(/"error":"invalid_request"/)
        .expect(/"error_description":"post_logout_redirect_uri not registered"/);
    });

    it('rejects invalid JWTs', function () {
      const params = {
        id_token_hint: 'not.a.jwt'
      };

      return this.agent.get(route)
        .query(params)
        .expect(400)
        .expect(/"error":"invalid_request"/)
        .expect(/"error_description":"could not decode id_token_hint/);
    });

    it('rejects JWTs with unrecognized client', function* () {
      const params = {
        id_token_hint: yield JWT.sign({
          aud: 'nonexistant'
        }, null, 'none')
      };

      return this.agent.get(route)
        .query(params)
        .expect(400)
        .expect(/"error":"invalid_request"/)
        .expect(/"error_description":"could not validate id_token_hint \(invalid_client\)/);
    });

    it('rejects JWTs with bad signatures', function* () {
      const params = {
        id_token_hint: yield JWT.sign({
          aud: 'client'
        }, null, 'none')
      };

      return this.agent.get(route)
        .query(params)
        .expect(400)
        .expect(/"error":"invalid_request"/)
        .expect(/"error_description":"could not validate id_token_hint/);
    });
  });

  describe('POST end_session', function () {
    it('checks session.logout is set', function () {
      return this.agent.post('/session/end')
        .send({})
        .type('form')
        .expect(400)
        .expect(/"error":"invalid_request"/)
        .expect(/"error_description":"could not find logout details"/);
    });

    it('checks session.logout.secret (xsrf is right)', function () {
      this.getSession().logout = { secret: '123' };

      return this.agent.post('/session/end')
        .send({ xsrf: 'not right' })
        .type('form')
        .expect(400)
        .expect(/"error":"invalid_request"/)
        .expect(/"error_description":"xsrf token invalid"/);
    });

    it('destroys complete session if user wants to', function () {
      const sessionId = this.getSessionId();
      const adapter = this.TestAdapter.for('Session');
      sinon.spy(adapter, 'destroy');

      this.getSession().logout = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      return this.agent.post('/session/end')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .expect(302)
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly');
          expect(adapter.destroy.called).to.be.true;
          expect(adapter.destroy.withArgs(sessionId).calledOnce).to.be.true;
        });
    });

    it('only clears one clients session if user doesnt wanna log out', function () {
      const adapter = this.TestAdapter.for('Session');
      sinon.spy(adapter, 'destroy');
      const session = this.getSession();
      session.logout = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      expect(session.authorizations.client).to.be.ok;

      return this.agent.post('/session/end')
        .send({ xsrf: '123' })
        .type('form')
        .expect(302)
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly');
          expect(response.headers['set-cookie']).to.contain('_state.client.sig=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly');
          expect(session.authorizations.client).to.be.undefined;
          expect(adapter.destroy.called).to.be.false;
        });
    });

    it('follows a domain if configured', function () {
      this.getSession().logout = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      i(this.provider).configuration().cookies.long.domain = '.oidc.dev';

      return this.agent.post('/session/end')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .expect(() => {
          delete i(this.provider).configuration().cookies.long.domain;
        })
        .expect(302)
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=.oidc.dev; httponly');
        });
    });
  });
});
