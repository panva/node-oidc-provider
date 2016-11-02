'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { decode: base64url } = require('base64url');
const { parse: parseUrl } = require('url');
const { expect } = require('chai');

const j = JSON.parse;
const route = '/token';

function errorDetail(spy) {
  return spy.args[0][0].error_detail;
}

describe('grant_type=refresh_token', function () {
  before(bootstrap(__dirname)); // agent, provider, this.TestAdapter

  describe('extends authorization_code', function () {
    // TODO: it('omits to issue a refresh_token if the client cannot use it (misses allowed grant)');
  });

  context('with real tokens', function () {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    beforeEach(function (done) {
      this.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid email',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb',
        nonce: 'foobarnonce'
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
          redirect_uri: 'https://client.example.com/cb'
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('refresh_token');
          const jti = response.body.refresh_token.substring(0, 48);
          this.refreshToken = this.TestAdapter.for('RefreshToken').syncFind(jti);
          this.rt = response.body.refresh_token;
        })
        .end(done);
      });
    });

    it('returns the right stuff', function () {
      const rt = this.rt;
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        refresh_token: rt,
        grant_type: 'refresh_token'
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token');
        const refreshIdToken = j(base64url(response.body.id_token.split('.')[1]));
        expect(refreshIdToken).to.have.property('nonce', 'foobarnonce');
        expect(response.body).to.have.property('refresh_token', rt);
      });
    });


    describe('validates', function () {
      context('', function () {
        before(function () {
          this.prev = this.provider.RefreshToken.expiresIn;
          i(this.provider).configuration('ttl').RefreshToken = 1;
        });

        after(function () {
          i(this.provider).configuration('ttl').RefreshToken = this.prev;
        });

        it('validates code is not expired', function (done) {
          const rt = this.rt;
          setTimeout(() => {
            const spy = sinon.spy();
            this.provider.once('grant.error', spy);

            return this.agent.post(route)
              .auth('client', 'secret')
              .send({
                refresh_token: rt,
                grant_type: 'refresh_token'
              })
              .type('form')
              .expect(400)
              .expect(() => {
                expect(spy.calledOnce).to.be.true;
                expect(errorDetail(spy)).to.equal('refresh token is expired');
              })
              .expect((response) => {
                expect(response.body).to.have.property('error', 'invalid_grant');
              })
              .end(done);
          }, 1000);
        });
      });

      it('validates that token belongs to client', function () {
        const rt = this.rt;
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        return this.agent.post(route)
          .auth('client2', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token'
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
        const rt = this.rt;
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
            scope: 'openid profile'
          })
          .type('form')
          .expect(400)
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_scope');
            expect(response.body).to.have.property('error_description', 'refresh token missing requested scope');
            expect(response.body).to.have.property('scope', 'profile');
          });
      });

      it('validates account is still there', function () {
        const rt = this.rt;
        sinon.stub(this.provider.Account, 'findById', () => {
          return Promise.resolve();
        });

        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token'
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
        grant_type: 'refresh_token'
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
      this.provider.once('grant.error', spy);
      return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'refresh_token',
        refresh_token: 'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiYzc4ZjdlYjMtZjdkYi00ZDNmLWFjNzUtYTY3MTA2NTUxOTYyIiwiaWF0IjoxNDYzNjY5Mjk1LCJleHAiOjE0NjM2NzEwOTUsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NjAxNDMifQ.KJxy5D3_lwAlBs6E0INhrjJm1Bk9BrPlRacoyYztt5s_yxWidNua_eSvMbmRqqIq6t2hGguW7ZkEJhVHGNxvaHctGjSIrAOjaZhh1noqP9keXnATf2N2Twdsz-Viim5F0A7vu9OlhNm75P-yfreOTmmbQ4goM5449Dvq_xli2gmgg1j4HnASAI3YuxAzCCSJPbJDE2UL0-_q7nIvH0Ak2RuNbTJLjYt36jymfLnJ2OOe1z9N2RuZrIQQy7ksAIJkJs_3SJ0RYKDBtUplPC2fK7qsNk4wUTgxLJE3Xp_sJZKwVG2ascsVdexVnUCxqDN3xt9MpI14M3Zw7UwGghdIfQ'
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
  });
});
