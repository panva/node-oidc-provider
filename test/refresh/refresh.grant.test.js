const { parse: parseUrl } = require('url');

const sinon = require('sinon');
const base64url = require('base64url');
const { expect } = require('chai');
const timekeeper = require('timekeeper');

const bootstrap = require('../test_helper');

const fail = () => { throw new Error('expected promise to be rejected'); };
const j = JSON.parse;
const route = '/token';

function errorDetail(spy) {
  return spy.args[0][0].error_detail;
}

describe('grant_type=refresh_token', () => {
  before(bootstrap(__dirname));

  afterEach(() => timekeeper.reset());

  context('with real tokens', () => {
    before(function () { return this.login({ scope: 'openid email' }); });
    after(function () { return this.logout(); });

    beforeEach(function (done) {
      this.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid email',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          nonce: 'foobarnonce',
        })
        .expect(302)
        .end((err, authResponse) => {
          if (err) {
            return done(err);
          }

          const { query: { code } } = parseUrl(authResponse.headers.location, true);

          return this.agent.post(route)
            .auth('client', 'secret')
            .type('form')
            .send({
              code,
              grant_type: 'authorization_code',
              redirect_uri: 'https://client.example.com/cb',
            })
            .expect(200)
            .expect((response) => {
              expect(response.body).to.have.property('refresh_token');
              const jti = this.getTokenJti(response.body.refresh_token);
              this.refreshToken = this.TestAdapter.for('RefreshToken').syncFind(jti, { payload: true });
              expect(this.refreshToken).to.have.property('gty', 'authorization_code');
              this.rt = response.body.refresh_token;
            })
            .end(done);
        });
    });

    afterEach(function () {
      this.provider.removeAllListeners('token.issued');
      this.provider.removeAllListeners('grant.revoked');
      this.provider.removeAllListeners('token.revoked');
    });

    it('returns the right stuff', function () {
      const { rt } = this;
      const spy = sinon.spy();
      this.provider.on('grant.success', spy);

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect(({ body }) => {
          expect(body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token', 'scope');
          const refreshIdToken = j(base64url.decode(body.id_token.split('.')[1]));
          expect(refreshIdToken).to.have.property('nonce', 'foobarnonce');
          expect(body).to.have.property('refresh_token').that.is.a('string');
        });
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'AccessToken', 'RefreshToken');
        expect(ctx.oidc.entities.RefreshToken).to.have.property('gty', 'authorization_code');
        expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'authorization_code refresh_token');
      }, done));

      this.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: this.rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .end(() => {});
    });

    describe('validates', () => {
      context('', () => {
        before(function () {
          const ttl = i(this.provider).configuration('ttl');
          this.prev = ttl.RefreshToken;
          ttl.RefreshToken = 5;
        });

        after(function () {
          i(this.provider).configuration('ttl').RefreshToken = this.prev;
        });

        it('validates the refresh token is not expired', function () {
          timekeeper.travel(Date.now() + (10 * 1000));
          const { rt } = this;
          const spy = sinon.spy();
          this.provider.on('grant.error', spy);

          return this.agent.post(route)
            .auth('client', 'secret')
            .send({
              refresh_token: rt,
              grant_type: 'refresh_token',
            })
            .type('form')
            .expect(400)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(errorDetail(spy)).to.equal('refresh token is expired');
            })
            .expect((response) => {
              expect(response.body).to.have.property('error', 'invalid_grant');
            });
        });
      });

      it('validates that token belongs to client', function () {
        const { rt } = this;
        const spy = sinon.spy();
        this.provider.on('grant.error', spy);

        return this.agent.post(route)
          .auth('client2', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(400)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('refresh token client mismatch');
          })
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_grant');
          });
      });

      it('scopes are not getting extended', function () {
        const { rt } = this;
        const spy = sinon.spy();
        this.provider.on('grant.error', spy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
            scope: 'openid profile',
          })
          .type('form')
          .expect(400)
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_scope');
            expect(response.body).to.have.property('error_description', 'refresh token missing requested scope');
            expect(response.body).to.have.property('scope', 'profile');
          });
      });

      it('scopes can get slimmer', function () {
        const { rt } = this;
        const spy = sinon.spy();
        this.provider.on('token.issued', spy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
            scope: 'openid',
          })
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            expect(spy.firstCall.args[0]).to.have.property('kind', 'AccessToken');
            expect(spy.firstCall.args[0]).to.have.property('scope', 'openid');
            expect(body).to.have.property('scope', 'openid');
          });
      });

      it('scopes can get slimmer but openid is still required', function () {
        const { rt } = this;
        const spy = sinon.spy();
        this.provider.on('grant.error', spy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
            scope: 'profile',
          })
          .type('form')
          .expect(400)
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_scope');
            expect(response.body).to.have.property('error_description', 'openid is required scope');
            expect(response.body).to.have.property('scope', 'profile');
          });
      });

      it('validates account is still there', function () {
        const { rt } = this;
        sinon.stub(this.provider.Account, 'findById').callsFake(() => Promise.resolve());

        const spy = sinon.spy();
        this.provider.on('grant.error', spy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(() => {
            this.provider.Account.findById.restore();
          })
          .expect(400)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('refresh token invalid (referenced account not found)');
          })
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_grant');
          });
      });
    });

    it('refresh_token presence', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_request');
          expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
          expect(response.body).to.have.property('error_description').and.matches(/refresh_token/);
        });
    });

    it('code being "found"', function () {
      const spy = sinon.spy();
      this.provider.on('grant.error', spy);
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'refresh_token',
          refresh_token: 'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiYzc4ZjdlYjMtZjdkYi00ZDNmLWFjNzUtYTY3MTA2NTUxOTYyIiwiaWF0IjoxNDYzNjY5Mjk1LCJleHAiOjE0NjM2NzEwOTUsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NjAxNDMifQ.KJxy5D3_lwAlBs6E0INhrjJm1Bk9BrPlRacoyYztt5s_yxWidNua_eSvMbmRqqIq6t2hGguW7ZkEJhVHGNxvaHctGjSIrAOjaZhh1noqP9keXnATf2N2Twdsz-Viim5F0A7vu9OlhNm75P-yfreOTmmbQ4goM5449Dvq_xli2gmgg1j4HnASAI3YuxAzCCSJPbJDE2UL0-_q7nIvH0Ak2RuNbTJLjYt36jymfLnJ2OOe1z9N2RuZrIQQy7ksAIJkJs_3SJ0RYKDBtUplPC2fK7qsNk4wUTgxLJE3Xp_sJZKwVG2ascsVdexVnUCxqDN3xt9MpI14M3Zw7UwGghdIfQ',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('refresh token not found');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    describe('refreshTokenRotation=rotateAndConsume', () => {
      before(function () {
        i(this.provider).configuration().refreshTokenRotation = 'rotateAndConsume';
      });

      after(function () {
        i(this.provider).configuration().refreshTokenRotation = 'none';
      });

      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'AccessToken', 'RotatedRefreshToken', 'RefreshToken');
          expect(ctx.oidc.entities.RotatedRefreshToken).not.to.eql(ctx.oidc.entities.RefreshToken);
          expect(ctx.oidc.entities.RotatedRefreshToken).to.have.property('gty', 'authorization_code');
          expect(ctx.oidc.entities.RefreshToken).to.have.property('gty', 'authorization_code refresh_token');
          expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'authorization_code refresh_token');
        }, done));

        this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: this.rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .end(() => {});
      });

      it('issues a new refresh token and consumes the old one', function () {
        const { rt } = this;
        const consumeSpy = sinon.spy();
        const issueSpy = sinon.spy();
        this.provider.on('token.consumed', consumeSpy);
        this.provider.on('token.issued', issueSpy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200)
          .expect(() => {
            expect(consumeSpy.calledOnce).to.be.true;
            expect(issueSpy.calledTwice).to.be.true;
          })
          .expect((response) => {
            expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token', 'scope');
            const refreshIdToken = j(base64url.decode(response.body.id_token.split('.')[1]));
            expect(refreshIdToken).to.have.property('nonce', 'foobarnonce');
            expect(response.body).to.have.property('refresh_token').not.equal(rt);
          });
      });

      it('the new refresh token has identical scope to the old one', function () {
        const { rt } = this;
        const consumeSpy = sinon.spy();
        const issueSpy = sinon.spy();
        this.provider.on('token.consumed', consumeSpy);
        this.provider.on('token.issued', issueSpy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200)
          .expect(() => {
            expect(consumeSpy.calledOnce).to.be.true;
            expect(issueSpy.calledTwice).to.be.true;
            expect(consumeSpy.firstCall.args[0]).to.have.property('scope', 'openid email');
            expect(issueSpy.firstCall.args[0]).to.have.property('scope', 'openid email');
          });
      });

      it('the new refresh token has identical scope to the old one even if the access token is requested with less scopes', function () {
        const { rt } = this;
        const consumeSpy = sinon.spy();
        const issueSpy = sinon.spy();
        this.provider.on('token.consumed', consumeSpy);
        this.provider.on('token.issued', issueSpy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            scope: 'openid',
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200)
          .expect(() => {
            expect(consumeSpy.calledOnce).to.be.true;
            expect(issueSpy.calledTwice).to.be.true;
            expect(consumeSpy.firstCall.args[0]).to.have.property('scope', 'openid email');
            expect(issueSpy.firstCall.args[0]).to.have.property('scope', 'openid email');
            expect(issueSpy.secondCall.args[0]).to.have.property('scope', 'openid');
          });
      });

      it('revokes the complete grant if the old token is used again', function () {
        const { rt } = this;

        const grantRevokeSpy = sinon.spy();
        const tokenRevokeSpy = sinon.spy();
        this.provider.on('grant.revoked', grantRevokeSpy);
        this.provider.on('token.revoked', tokenRevokeSpy);

        return Promise.all([
          this.agent.post(route)
            .auth('client', 'secret')
            .send({
              refresh_token: rt,
              grant_type: 'refresh_token',
            })
            .type('form')
            .expect(200), // one of them will fail.
          this.agent.post(route)
            .auth('client', 'secret')
            .send({
              refresh_token: rt,
              grant_type: 'refresh_token',
            })
            .type('form')
            .expect(200), // one of them will fail.
        ]).then(fail, () => {
          expect(grantRevokeSpy.calledOnce).to.be.true;
          expect(tokenRevokeSpy.calledOnce).to.be.true;
        });
      });
    });
  });
});
