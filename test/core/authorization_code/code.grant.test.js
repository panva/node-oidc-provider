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
  redirect_uris: ['https://client.example.com/cb']
});
provider.setupCerts();

function errorDetail(spy) {
  return spy.args[0][0].error_detail;
}

describe('grant_type=authorization_code', function () {
  context('with real tokens', function () {
    before(agent.login);
    after(agent.logout);

    beforeEach(function () {
      return agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .expect(302)
      .expect((response) => {
        const { query: { code } } = parseUrl(response.headers.location, true);
        const jti = j(base64url(code.split('.')[0])).jti;
        this.code = provider.AuthorizationCode.adapter.syncFind(jti);
        this.ac = code;
      });
    });

    it('returns the right stuff', function () {
      const spy = sinon.spy();
      provider.once('grant.success', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      }))
      .expect(200)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(function (response) {
        expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type');
        expect(response.body).not.to.have.key('refresh_token');
      });
    });

    context('', function () {
      before(function () {
        this.prev = provider.AuthorizationCode.expiresIn;
        provider.AuthorizationCode.expiresIn = 1;
      });

      after(function () {
        provider.AuthorizationCode.expiresIn = this.prev;
      });

      it('validates code is not expired', function (done) {
        setTimeout(() => {
          const spy = sinon.spy();
          provider.once('grant.error', spy);

          return agent.post(route)
          .auth('client', 'secret')
          .send(qs({
            code: this.ac,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb'
          }))
          .expect(400)
          .expect(function () {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('authorization code is expired');
          })
          .expect(function (response) {
            expect(response.body).to.have.property('error', 'invalid_grant');
          })
          .end(done);
        }, 1000);
      });
    });


    it('validates code is not already used', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      this.code.consumed = Date.now() / 1000 | 0;

      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      }))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code already consumed');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('consumes the code', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      }))
      .expect(() => {
        expect(this.code).to.have.property('consumed').and.be.most(Date.now() / 1000 | 0);
      })
      .expect(200);
    });

    it('validates code belongs to client', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client2', 'secret')
      .send(qs({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      }))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code client mismatch');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('validates used redirect_uri', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb?thensome'
      }))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code redirect_uri mismatch');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('validates account is still there', function () {
      sinon.stub(provider.Account, 'findById', function () {
        return Promise.resolve();
      });

      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      }))
      .expect(function () {
        provider.Account.findById.restore();
      })
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code invalid (referenced account not found)');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });
  });

  describe('validates', function () {
    it('grant_type presence', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({}))
      .expect(400)
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
        expect(response.body).to.have.property('error_description').and.matches(/grant_type/);
      });
    });

    it('code presence', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs(
        {
          grant_type: 'authorization_code',
          redirect_uri: 'blah'
        }
      ))
      .expect(400)
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
        expect(response.body).to.have.property('error_description').and.matches(/code/);
      });
    });

    it('redirect_uri presence', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs(
        {
          grant_type: 'authorization_code',
          code: 'blah'
        }
      ))
      .expect(400)
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
        expect(response.body).to.have.property('error_description').and.matches(/redirect_uri/);
      });
    });

    it('code being "found"', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);
      return agent.post(route)
      .auth('client', 'secret')
      .send(qs(
        {
          grant_type: 'authorization_code',
          redirect_uri: 'http://client.example.com',
          code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw'
        }
      ))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code not found');
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });
  });

  describe('error handling', function () {
    before(function () {
      sinon.stub(provider.Client, 'find').returns(Promise.reject(new Error()));
    });

    after(function () {
      provider.Client.find.restore();
    });

    it('handles errors', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .send(qs({}))
      .expect(400)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(function (response) {
        expect(response.body).not.to.have.property('error', 'server_error');
      });
    });

    it('handles exceptions', function () {
      const spy = sinon.spy();
      provider.once('server_error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send(qs({
        grant_type: 'authorization_code',
        code: 'code',
        redirect_uri: 'is there too'
      }))
      .expect(500)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(function (response) {
        expect(response.body).to.have.property('error', 'server_error');
        expect(response.body).to.have.property('error_description', 'oops something went wrong');
      });
    });
  });
});
