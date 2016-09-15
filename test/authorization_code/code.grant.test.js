'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { parse: parseUrl } = require('url');
const { expect } = require('chai');
const epochTime = require('../../lib/helpers/epoch_time');

const route = '/token';

function errorDetail(spy) {
  return spy.args[0][0].error_detail;
}

describe('grant_type=authorization_code', () => {
  const {
    agent, provider, TestAdapter
  } = bootstrap(__dirname);


  provider.setupClient();
  provider.setupClient({
    client_id: 'client2',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  });
  const AuthorizationCode = provider.AuthorizationCode;

  context('with real tokens', () => {
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
        const jti = code.substring(0, 48);
        this.code = TestAdapter.for('AuthorizationCode').syncFind(jti);
        this.ac = code;
      });
    });

    it('returns the right stuff', function () {
      const spy = sinon.spy();
      provider.once('grant.success', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .type('form')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type');
        expect(response.body).not.to.have.key('refresh_token');
      });
    });

    it('returns token-endpoint-like cache headers', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .type('form')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .expect('pragma', 'no-cache')
      .expect('cache-control', 'no-cache, no-store');
    });

    it('handles internal token signature validation', function () {
      sinon.stub(AuthorizationCode, 'fromJWT', () => {
        return Promise.reject(new Error());
      });

      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .type('form')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .expect(() => {
        AuthorizationCode.fromJWT.restore();
      })
      .expect(401)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_token');
      });
    });

    context('', () => {
      before(function () {
        this.prev = AuthorizationCode.expiresIn;
        provider.configuration('ttl').AuthorizationCode = 1;
      });

      after(function () {
        provider.configuration('ttl').AuthorizationCode = this.prev;
      });

      it('validates code is not expired', function (done) {
        setTimeout(() => {
          const spy = sinon.spy();
          provider.once('grant.error', spy);

          return agent.post(route)
          .auth('client', 'secret')
          .send({
            code: this.ac,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb'
          })
          .type('form')
          .expect(400)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('authorization code is expired');
          })
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_grant');
          })
          .end(done);
        }, 1000);
      });
    });


    it('validates code is not already used', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      this.code.consumed = epochTime();

      return agent.post(route)
      .auth('client', 'secret')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .type('form')
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code already consumed');
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('consumes the code', function () {
      return agent.post(route)
      .auth('client', 'secret')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .type('form')
      .expect(() => {
        expect(this.code).to.have.property('consumed').and.be.most(epochTime());
      })
      .expect(200);
    });

    it('validates code belongs to client', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client2', 'secret')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .type('form')
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code client mismatch');
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('validates used redirect_uri', function () {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb?thensome'
      })
      .type('form')
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code redirect_uri mismatch');
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('validates account is still there', function () {
      sinon.stub(provider.Account, 'findById', () => {
        return Promise.resolve();
      });

      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send({
        code: this.ac,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb'
      })
      .type('form')
      .expect(() => {
        provider.Account.findById.restore();
      })
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code invalid (referenced account not found)');
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });
  });

  describe('validates', () => {
    it('grant_type presence', () => {
      return agent.post(route)
      .auth('client', 'secret')
      .send({})
      .type('form')
      .expect(400)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
        expect(response.body).to.have.property('error_description').and.matches(/grant_type/);
      });
    });

    it('code presence', () => {
      return agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'authorization_code',
        redirect_uri: 'blah'
      })
      .type('form')
      .expect(400)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
        expect(response.body).to.have.property('error_description').and.matches(/code/);
      });
    });

    it('redirect_uri presence', () => {
      return agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'authorization_code',
        code: 'blah'
      })
      .type('form')
      .expect(400)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_request');
        expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
        expect(response.body).to.have.property('error_description').and.matches(/redirect_uri/);
      });
    });

    it('code being "found"', () => {
      const spy = sinon.spy();
      provider.once('grant.error', spy);
      return agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'authorization_code',
        redirect_uri: 'http://client.example.com',
        code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw'
      })
      .type('form')
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('authorization code not found');
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_grant');
      });
    });

    it('code being "valid format"', () => {
      const spy = sinon.spy();
      provider.once('grant.error', spy);
      return agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'authorization_code',
        redirect_uri: 'http://client.example.com',
        code: 'not even close'
      }
      )
      .type('form')
      .expect(401)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'invalid_token');
      });
    });
  });

  describe('error handling', () => {
    before(() => {
      sinon.stub(provider.Client, 'find').returns(Promise.reject(new Error()));
    });

    after(() => {
      provider.Client.find.restore();
    });

    it('handles errors', () => {
      const spy = sinon.spy();
      provider.once('grant.error', spy);

      return agent.post(route)
      .send({})
      .type('form')
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).not.to.have.property('error', 'server_error');
      });
    });

    it('handles exceptions', () => {
      const spy = sinon.spy();
      provider.once('server_error', spy);

      return agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'authorization_code',
        code: 'code',
        redirect_uri: 'is there too'
      })
      .type('form')
      .expect(500)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.property('error', 'server_error');
        expect(response.body).to.have.property('error_description', 'oops something went wrong');
      });
    });
  });
});
