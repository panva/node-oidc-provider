const { parse: parseUrl } = require('url');

const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');
const { InvalidClient, InvalidRequest } = require('../../lib/helpers/errors');

const route = '/session/end';

describe('logout endpoint', () => {
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

  ['get', 'post'].forEach((verb) => {
    describe(`${verb.toUpperCase()} end_session`, () => {
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

          return this.wrap({ route, verb, params })
            .expect(200)
            .expect(() => {
              const { state: { postLogoutRedirectUri } } = this.getSession();
              expect(postLogoutRedirectUri).to.equal('https://client.example.com/logout/cb');
            });
        });

        it('populates ctx.oidc.entities', function (done) {
          this.provider.use(this.assertOnce((ctx) => {
            expect(ctx.oidc.entities).to.have.keys('Client', 'IdTokenHint');
          }, done));

          const params = {
            id_token_hint: this.idToken,
            post_logout_redirect_uri: 'https://client.example.com/logout/cb',
          };

          this.wrap({ route, verb, params })
            .end(() => {});
        });

        it('also forwards the state if provided', function () {
          const params = {
            id_token_hint: this.idToken,
            post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            state: 'foobar',
          };

          return this.wrap({ route, verb, params })
            .expect(200)
            .expect(() => {
              const { state: { postLogoutRedirectUri, state } } = this.getSession();
              expect(postLogoutRedirectUri).to.equal('https://client.example.com/logout/cb');
              expect(state).to.equal('foobar');
            });
        });

        it('can omit the post_logout_redirect_uri and uses the default one', function () {
          const params = { id_token_hint: this.idToken };

          return this.wrap({ route, verb, params })
            .expect(200)
            .expect(() => {
              const { state: { postLogoutRedirectUri } } = this.getSession();
              expect(postLogoutRedirectUri).to.equal(`${this.provider.issuer}/session/end/success`);
            });
        });
      });

      it('without id_token_hint post_logout_redirect_uri may not be provided', function () {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        this.provider.once('end_session.error', emitSpy);
        const params = {
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
            expect(renderArgs[1]).to.have.property('error_description', 'post_logout_redirect_uri can only be used in combination with id_token_hint');
            expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
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
            iss: this.provider.issuer,
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
            iss: this.provider.issuer,
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
  });

  describe('POST end_session_confirm', () => {
    it('checks session.state is set', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session_confirm.error', emitSpy);
      return this.agent.post('/session/end/confirm')
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

    it('checks session.state.secret (xsrf is right)', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session_confirm.error', emitSpy);
      this.getSession().state = { secret: '123' };

      return this.agent.post('/session/end/confirm')
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

      this.getSession().state = { secret: '123', postLogoutRedirectUri: '/', clientId: 'client' };

      this.agent.post('/session/end/confirm')
        .send({ xsrf: '123', logout: 'yes' })
        .type('form')
        .end(() => {});
    });

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
          expect(adapter.destroy.called).to.be.true;
          expect(adapter.upsert.called).not.to.be.true;
          expect(adapter.destroy.withArgs(sessionId).calledOnce).to.be.true;
          expect(parseUrl(response.headers.location, true).query).not.to.have.property('client_id');
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
          expect(session.authorizations.client).to.be.undefined;
          expect(session.state).to.be.undefined;
          expect(this.getSessionId()).not.to.eql(oldId);
          expect(adapter.destroy.calledOnceWith(oldId)).to.be.true;
          expect(parseUrl(response.headers.location, true).query.client_id).to.eql('client');
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
        .expect('location', '/?state=foobar');
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
        .expect(() => {
          delete i(this.provider).configuration().cookies.long.domain;
        })
        .expect(302);
    });
  });

  describe('GET end_session_success', () => {
    it('calls the postLogoutSuccessSource helper', function () {
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'postLogoutSuccessSource');
      return this.agent.get('/session/end/success')
        .set('Accept', 'text/html')
        .expect(() => {
          renderSpy.restore();
        })
        .expect(200)
        .expect(() => {
          expect(renderSpy.calledOnce).to.be.true;
          const [ctx] = renderSpy.args[0];
          expect(ctx.oidc.client).to.be.undefined;
        });
    });

    it('has the client loaded when present', function () {
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'postLogoutSuccessSource');
      return this.agent.get('/session/end/success?client_id=client')
        .set('Accept', 'text/html')
        .expect(() => {
          renderSpy.restore();
        })
        .expect(200)
        .expect(() => {
          expect(renderSpy.calledOnce).to.be.true;
          const [ctx] = renderSpy.args[0];
          expect(ctx.oidc.client).to.be.ok;
        });
    });

    it('throws when the client is not found', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
      this.provider.once('end_session_success.error', emitSpy);
      return this.agent.get('/session/end/success?client_id=foobar')
        .set('Accept', 'text/html')
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_client');
          expect(renderArgs[2]).to.be.an.instanceof(InvalidClient);
        });
    });
  });
});
