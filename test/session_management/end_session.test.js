const { parse: parseUrl } = require('url');

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('[session_management]', () => {
  before(bootstrap(__dirname));

  beforeEach(function () { return this.login(); });
  afterEach(function () { return this.logout(); });
  afterEach(sinon.restore);

  beforeEach(function () {
    return this.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid',
        nonce: String(Math.random()),
        response_type: 'id_token',
        redirect_uri: 'https://client.example.com/cb',
      })
      .expect(302)
      .expect((response) => {
        const { query: { id_token: idToken } } = parseUrl(response.headers.location.replace('#', '?'), true);
        this.idToken = idToken;
      });
  });

  describe('POST end_session', () => {
    it('destroys complete session if user wants to', function () {
      const sessionId = this.getSessionId();
      const adapter = this.TestAdapter.for('Session');
      sinon.spy(adapter, 'destroy');
      sinon.spy(adapter, 'upsert');

      this.getSession().state = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      return this.agent.post('/session/end/confirm')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .expect(302)
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; samesite=none; httponly');
          expect(response.headers['set-cookie']).to.contain('_state.client.legacy=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly');
          expect(adapter.destroy.called).to.be.true;
          expect(adapter.upsert.called).not.to.be.true;
          expect(adapter.destroy.withArgs(sessionId).calledOnce).to.be.true;
        });
    });

    it('only clears one clients session if user doesnt wanna log out', function () {
      const adapter = this.TestAdapter.for('Session');
      sinon.spy(adapter, 'destroy');
      let session = this.getSession();
      const oldId = this.getSessionId();
      session.state = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      expect(session.authorizations.client).to.be.ok;

      return this.agent.post('/session/end/confirm')
        .send({ xsrf: '123' })
        .type('form')
        .expect(302)
        .expect((response) => {
          session = this.getSession();
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; samesite=none; httponly');
          expect(response.headers['set-cookie']).to.contain('_state.client.legacy=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly');
          expect(session.authorizations.client).to.be.undefined;
          expect(session.state).to.be.undefined;
          expect(this.getSessionId()).not.to.eql(oldId);
          expect(adapter.destroy.calledOnceWith(oldId)).to.be.true;
        });
    });

    it('follows a domain if configured', function () {
      this.getSession().state = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      i(this.provider).configuration().cookies.long.domain = '.oidc.dev';

      return this.agent.post('/session/end/confirm')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .expect(() => {
          delete i(this.provider).configuration().cookies.long.domain;
        })
        .expect(302)
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=.oidc.dev; samesite=none; httponly');
          expect(response.headers['set-cookie']).to.contain('_state.client.legacy=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=.oidc.dev; httponly');
        });
    });

    it('forwards the state too', function () {
      this.getSession().state = {
        secret: '123', postLogoutRedirectUri: '/', clientId: 'client', state: 'foobar',
      };

      i(this.provider).configuration().cookies.long.domain = '.oidc.dev';

      return this.agent.post('/session/end/confirm')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .expect(() => {
          delete i(this.provider).configuration().cookies.long.domain;
        })
        .expect(302)
        .expect('location', '/?state=foobar')
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=.oidc.dev; samesite=none; httponly');
          expect(response.headers['set-cookie']).to.contain('_state.client.legacy=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=.oidc.dev; httponly');
        });
    });

    it('handles a no existing session state', async function () {
      Object.assign(this.getSession(), {
        state: {
          secret: '123', postLogoutRedirectUri: '/', clientId: 'client', state: 'foobar',
        },
        authorizations: undefined,
      });

      return this.agent.post('/session/end/confirm')
        .send({ xsrf: '123' })
        .type('form')
        .expect(302);
    });
  });
});
