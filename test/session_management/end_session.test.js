const { parse: parseUrl } = require('url');

const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');
const { InvalidRequest } = require('../../lib/helpers/errors');

const route = '/session/end';

describe('[session_management]', () => {
  before(bootstrap(__dirname));

  beforeEach(function () { return this.login(); });
  afterEach(function () { return this.logout(); });
  afterEach(function () {
    if (this.TestAdapter.for('Session').destroy.restore) {
      this.TestAdapter.for('Session').destroy.restore();
    }
    if (this.TestAdapter.for('Session').upsert.restore) {
      this.TestAdapter.for('Session').upsert.restore();
    }
  });

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

  describe('GET end_session', () => {
    context('client with postLogoutRedirectUris', () => {
      before(async function () {
        (await this.provider.Client.find('client')).postLogoutRedirectUris = ['https://client.example.com/logout/cb'];
      });
      after(async function () {
        (await this.provider.Client.find('client')).postLogoutRedirectUris = [];
      });

      it('allows to redirect there', function () {
        const params = {
          id_token_hint: this.idToken,
          post_logout_redirect_uri: 'https://client.example.com/logout/cb',
        };

        return this.agent.get(route)
          .query(params)
          .expect(200)
          .expect(() => {
            const { logout: { postLogoutRedirectUri } } = this.getSession();
            expect(postLogoutRedirectUri).to.equal('https://client.example.com/logout/cb');
          });
      });

      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client');
        }, done));

        const params = {
          id_token_hint: this.idToken,
          post_logout_redirect_uri: 'https://client.example.com/logout/cb',
        };

        this.agent.get(route)
          .query(params)
          .end(() => {});
      });

      it('also forwards the state if provided', function () {
        const params = {
          id_token_hint: this.idToken,
          post_logout_redirect_uri: 'https://client.example.com/logout/cb',
          state: 'foobar',
        };

        return this.agent.get(route)
          .query(params)
          .expect(200)
          .expect(() => {
            const { logout: { postLogoutRedirectUri, state } } = this.getSession();
            expect(postLogoutRedirectUri).to.equal('https://client.example.com/logout/cb');
            expect(state).to.equal('foobar');
          });
      });

      it('can omit the post_logout_redirect_uri and uses the provider one', function () {
        const params = { id_token_hint: this.idToken };

        return this.agent.get(route)
          .query(params)
          .expect(200)
          .expect(() => {
            const { logout: { postLogoutRedirectUri } } = this.getSession();
            expect(postLogoutRedirectUri).to.equal(this.provider.issuer);
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
          expect(postLogoutRedirectUri).to.equal(this.provider.issuer);
        });
    });

    it('validates post_logout_redirect_uri allowed on client', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session.error', emitSpy);
      const params = {
        id_token_hint: this.idToken,
        post_logout_redirect_uri: 'https://client.example.com/callback/logout',
      };

      return this.agent.get(route)
        .set('Accept', 'text/html')
        .query(params)
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_request');
          expect(renderArgs[1]).to.have.property('error_description', 'post_logout_redirect_uri not registered');
          expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
        });
    });

    it('rejects invalid JWTs', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session.error', emitSpy);
      const params = {
        id_token_hint: 'not.a.jwt',
      };

      return this.agent.get(route)
        .set('Accept', 'text/html')
        .query(params)
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_request');
          expect(renderArgs[1]).to.have.property('error_description').that.matches(/could not decode id_token_hint/);
          expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
        });
    });

    it('rejects JWTs with unrecognized client', async function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session.error', emitSpy);
      const params = {
        id_token_hint: await JWT.sign({
          aud: 'nonexistant',
        }, null, 'none'),
      };

      return this.agent.get(route)
        .set('Accept', 'text/html')
        .query(params)
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_request');
          expect(renderArgs[1]).to.have.property('error_description', 'could not validate id_token_hint (invalid_client)');
          expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
        });
    });

    it('rejects JWTs with bad signatures', async function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session.error', emitSpy);
      const params = {
        id_token_hint: await JWT.sign({
          aud: 'client',
        }, null, 'none'),
      };

      return this.agent.get(route)
        .set('Accept', 'text/html')
        .query(params)
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_request');
          expect(renderArgs[1]).to.have.property('error_description').and.matches(/could not validate id_token_hint/);
          expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
        });
    });
  });

  describe('POST end_session', () => {
    it('checks session.logout is set', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session.error', emitSpy);
      return this.agent.post('/session/end')
        .set('Accept', 'text/html')
        .send({})
        .type('form')
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_request');
          expect(renderArgs[1]).to.have.property('error_description', 'could not find logout details');
          expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
        });
    });

    it('checks session.logout.secret (xsrf is right)', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session.error', emitSpy);
      this.getSession().logout = { secret: '123' };

      return this.agent.post('/session/end')
        .set('Accept', 'text/html')
        .send({ xsrf: 'not right' })
        .type('form')
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_request');
          expect(renderArgs[1]).to.have.property('error_description', 'xsrf token invalid');
          expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
        });
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client');
      }, done));

      this.getSession().logout = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      this.agent.post('/session/end')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .end(() => {});
    });

    it('destroys complete session if user wants to', function () {
      const sessionId = this.getSessionId();
      const adapter = this.TestAdapter.for('Session');
      sinon.spy(adapter, 'destroy');
      sinon.spy(adapter, 'upsert');

      this.getSession().logout = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      return this.agent.post('/session/end')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .expect(302)
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly');
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
      session.logout = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      expect(session.authorizations.client).to.be.ok;

      return this.agent.post('/session/end')
        .send({ xsrf: '123' })
        .type('form')
        .expect(302)
        .expect((response) => {
          session = this.getSession();
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly');
          expect(session.authorizations.client).to.be.undefined;
          expect(session.logout).to.be.undefined;
          expect(this.getSessionId()).not.to.eql(oldId);
          expect(adapter.destroy.calledOnceWith(oldId)).to.be.true;
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

    it('forwards the state too', function () {
      this.getSession().logout = {
        secret: '123', postLogoutRedirectUri: '/', clientId: 'client', state: 'foobar',
      };

      i(this.provider).configuration().cookies.long.domain = '.oidc.dev';

      return this.agent.post('/session/end')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .expect(() => {
          delete i(this.provider).configuration().cookies.long.domain;
        })
        .expect(302)
        .expect('location', '/?state=foobar')
        .expect((response) => {
          expect(response.headers['set-cookie']).to.contain('_state.client=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=.oidc.dev; httponly');
        });
    });

    it('handles a no existing session state', async function () {
      Object.assign(this.getSession(), {
        logout: {
          secret: '123', postLogoutRedirectUri: '/', clientId: 'client', state: 'foobar',
        },
        authorizations: undefined,
      });

      return this.agent.post('/session/end')
        .send({ xsrf: '123' })
        .type('form')
        .expect(() => {
          delete i(this.provider).configuration().cookies.long.domain;
        })
        .expect(302);
    });
  });
});
