'use strict';

const {
  agent, provider
} = require('../../test_helper')(__dirname);
const sinon = require('sinon');
const { decode: base64url } = require('base64url');
const { parse: parseUrl } = require('url');
const { stringify: qs } = require('querystring');
const { expect } = require('chai');
const j = JSON.parse;

const route = '/token';

provider.setupClient();
provider.setupClient({
  client_id: 'client2',
  client_secret: 'secret',
  grant_types: ['authorization_code', 'refresh_token'],
  redirect_uris: ['https://client.example.com/cb']
});
provider.setupCerts();

function errorDetail(spy) {
  return spy.args[0][0].error_detail;
}

describe('grant_type=refresh_token', function () {
  describe('extends authorization_code', function () {
    it('omits to issue a refresh_token if the client cannot use it (misses allowed grant)');
  });

  context('with real tokens', function () {
    before(agent.login);
    after(agent.logout);

    beforeEach(function (done) {
      return agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .expect(302)
      .end((err, authResponse) => {
        if (err) {
          return done(err);
        }

        const { query: { code } } = parseUrl(authResponse.headers.location, true);

        return agent.post(route)
        .auth('client', 'secret')
        .send(qs(
          {
            code,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb'
          }
        ))
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('refresh_token');
          const jti = j(base64url(response.body.refresh_token.split('.')[0])).jti;
          this.refreshToken = provider.RefreshToken.adapter.syncFind(jti);
          this.rt = response.body.refresh_token;
        })
        .end(done);
      });
    });

    it('returns the right stuff', function () {
      const rt = this.rt;
      const spy = sinon.spy();
      provider.once('grant.success', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        refresh_token: rt,
        grant_type: 'refresh_token'
      }))
      .expect(200)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(function (response) {
        expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token');
        expect(response.body).to.have.property('refresh_token', rt);
      });
    });

    context('', function () {
      before(function () {
        this.prev = provider.RefreshToken.expiresIn;
        provider.RefreshToken.expiresIn = 1;
      });

      after(function () {
        provider.RefreshToken.expiresIn = this.prev;
      });

      it('validates code is not expired', function (done) {
        const rt = this.rt;
        setTimeout(() => {
          const spy = sinon.spy();
          provider.once('grant.error', spy);

          return agent.post(route)
          .auth('client', 'secret')
          .send(qs({
            refresh_token: rt,
            grant_type: 'refresh_token'
          }))
          .expect(400)
          .expect(function () {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('refresh token is expired');
          })
          .expect(function (response) {
            expect(response.body).to.have.property('error', 'invalid_grant');
          })
          .end(done);
        }, 1000);
      });
    });

    it('validates that token belongs to client', function () {
      const rt = this.rt;
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client2', 'secret')
      .send(qs({
        refresh_token: rt,
        grant_type: 'refresh_token'
      }))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('refresh token client mismatch');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('validates scopes are not getting broadened');

    it('validates account is still there', function () {
      const rt = this.rt;
      sinon.stub(provider.Account, 'findById', function () {
        return Promise.resolve();
      });

      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        refresh_token: rt,
        grant_type: 'refresh_token'
      }))
      .expect(function () {
        provider.Account.findById.restore();
      })
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('refresh token invalid (referenced account not found)');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });
  });

  describe('validates', function () {
    it('refresh_token presence', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs(
        {
          grant_type: 'refresh_token'
        }
      ))
      .expect(400)
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
        expect(response.body).to.have.property('error_description').and.matches(/refresh_token/);
      });
    });

    it('code being "found"', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs(
        {
          grant_type: 'refresh_token',
          refresh_token: 'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiYzc4ZjdlYjMtZjdkYi00ZDNmLWFjNzUtYTY3MTA2NTUxOTYyIiwiaWF0IjoxNDYzNjY5Mjk1LCJleHAiOjE0NjM2NzEwOTUsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NjAxNDMifQ.KJxy5D3_lwAlBs6E0INhrjJm1Bk9BrPlRacoyYztt5s_yxWidNua_eSvMbmRqqIq6t2hGguW7ZkEJhVHGNxvaHctGjSIrAOjaZhh1noqP9keXnATf2N2Twdsz-Viim5F0A7vu9OlhNm75P-yfreOTmmbQ4goM5449Dvq_xli2gmgg1j4HnASAI3YuxAzCCSJPbJDE2UL0-_q7nIvH0Ak2RuNbTJLjYt36jymfLnJ2OOe1z9N2RuZrIQQy7ksAIJkJs_3SJ0RYKDBtUplPC2fK7qsNk4wUTgxLJE3Xp_sJZKwVG2ascsVdexVnUCxqDN3xt9MpI14M3Zw7UwGghdIfQ'
        }
      ))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('refresh token not found');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });
  });
});
