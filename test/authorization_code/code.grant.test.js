const { parse: parseUrl } = require('url');

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');
const timekeeper = require('timekeeper');

const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const route = '/token';

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('grant_type=authorization_code', () => {
  before(bootstrap(__dirname));

  afterEach(() => timekeeper.reset());

  afterEach(function () {
    this.provider.removeAllListeners('grant.success');
    this.provider.removeAllListeners('grant.error');
    this.provider.removeAllListeners('server_error');
  });

  context('with real tokens (1/2) - more than two redirect_uris registered', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    beforeEach(function () {
      return this.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(302)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = this.getTokenJti(code);
          this.code = this.TestAdapter.for('AuthorizationCode').syncFind(jti);
          this.ac = code;
        });
    });

    it('returns the right stuff', function () {
      const spy = sinon.spy();
      this.provider.on('grant.success', spy);

      return this.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect((response) => {
          expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'scope');
          expect(response.body).not.to.have.key('refresh_token');
        });
    });

    it('populates ctx.oidc.entities (no offline_access)', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'AuthorizationCode', 'AccessToken');
        expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'authorization_code');
      }, done));

      this.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .end(() => {});
    });

    it('populates ctx.oidc.entities (w/ offline_access)', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'AuthorizationCode', 'AccessToken', 'RefreshToken');
        expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'authorization_code');
        expect(ctx.oidc.entities.RefreshToken).to.have.property('gty', 'authorization_code');
      }, done));

      this.getSession().authorizations.client.promptedScopes.push('offline_access');
      this.TestAdapter.for('AuthorizationCode').syncUpdate(this.getTokenJti(this.ac), {
        scope: 'openid offline_access',
      });
      this.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .end(() => {});
    });

    it('returns token-endpoint-like cache headers', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store');
    });

    context('', () => {
      before(function () {
        const ttl = i(this.provider).configuration('ttl');
        this.prev = ttl.AuthorizationCode;
        ttl.AuthorizationCode = 5;
      });

      after(function () {
        i(this.provider).configuration('ttl').AuthorizationCode = this.prev;
      });

      it('validates code is not expired', function () {
        timekeeper.travel(Date.now() + (10 * 1000));
        const spy = sinon.spy();
        this.provider.on('grant.error', spy);

        return this.agent.post(route)
          .auth('client', 'secret')
          .send({
            code: this.ac,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .expect(400)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('authorization code is expired');
          })
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_grant');
          });
      });
    });

    it('validates code is not already used', function () {
      const grantErrorSpy = sinon.spy();
      const grantRevokeSpy = sinon.spy();
      const tokenDestroySpy = sinon.spy();
      this.provider.on('grant.error', grantErrorSpy);
      this.provider.on('grant.revoked', grantRevokeSpy);
      this.provider.on('authorization_code.destroyed', tokenDestroySpy);

      this.code.consumed = epochTime();

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          expect(grantRevokeSpy.calledOnce).to.be.true;
          expect(tokenDestroySpy.calledOnce).to.be.true;
          expect(grantErrorSpy.calledOnce).to.be.true;
          expect(errorDetail(grantErrorSpy)).to.equal('authorization code already consumed');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('consumes the code', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(() => {
          expect(this.code).to.have.property('consumed').and.be.most(epochTime());
        })
        .expect(200);
    });

    it('validates code belongs to client', function () {
      const spy = sinon.spy();
      this.provider.on('grant.error', spy);

      return this.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
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

    it('validates a grant type is supported', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: this.ac,
          grant_type: 'foobar',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'unsupported_grant_type');
        });
    });

    it('validates used redirect_uri', function () {
      const spy = sinon.spy();
      this.provider.on('grant.error', spy);

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb?thensome',
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
      sinon.stub(this.provider.Account, 'findAccount').callsFake(() => Promise.resolve());

      const spy = sinon.spy();
      this.provider.on('grant.error', spy);

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(() => {
          this.provider.Account.findAccount.restore();
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

  context('with real tokens (2/2) - one redirect_uri registered', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    beforeEach(function () {
      return this.agent.get('/auth')
        .query({
          client_id: 'client2',
          scope: 'openid',
          response_type: 'code',
        })
        .expect(302)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = this.getTokenJti(code);
          this.code = this.TestAdapter.for('AuthorizationCode').syncFind(jti);
          this.ac = code;
        });
    });

    it('returns the right stuff', function () {
      const spy = sinon.spy();
      this.provider.on('grant.success', spy);

      return this.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
        })
        .expect(200)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect((response) => {
          expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'scope');
          expect(response.body).not.to.have.key('refresh_token');
        });
    });

    it('populates ctx.oidc.entities (no offline_access)', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'AuthorizationCode', 'AccessToken');
        expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'authorization_code');
      }, done));

      this.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
        })
        .end(() => {});
    });

    it('populates ctx.oidc.entities (w/ offline_access)', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'AuthorizationCode', 'AccessToken', 'RefreshToken');
        expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'authorization_code');
        expect(ctx.oidc.entities.RefreshToken).to.have.property('gty', 'authorization_code');
      }, done));

      this.getSession().authorizations.client2.promptedScopes.push('offline_access');
      this.TestAdapter.for('AuthorizationCode').syncUpdate(this.getTokenJti(this.ac), {
        scope: 'openid offline_access',
      });
      this.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
        })
        .end(() => {});
    });

    it('returns token-endpoint-like cache headers', function () {
      return this.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
        })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store');
    });

    context('', () => {
      before(function () {
        const ttl = i(this.provider).configuration('ttl');
        this.prev = ttl.AuthorizationCode;
        ttl.AuthorizationCode = 5;
      });

      after(function () {
        i(this.provider).configuration('ttl').AuthorizationCode = this.prev;
      });

      it('validates code is not expired', function () {
        timekeeper.travel(Date.now() + (10 * 1000));
        const spy = sinon.spy();
        this.provider.on('grant.error', spy);

        return this.agent.post(route)
          .auth('client2', 'secret')
          .send({
            code: this.ac,
            grant_type: 'authorization_code',
          })
          .type('form')
          .expect(400)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('authorization code is expired');
          })
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_grant');
          });
      });
    });

    it('validates code is not already used', function () {
      const grantErrorSpy = sinon.spy();
      const grantRevokeSpy = sinon.spy();
      const tokenDestroySpy = sinon.spy();
      this.provider.on('grant.error', grantErrorSpy);
      this.provider.on('grant.revoked', grantRevokeSpy);
      this.provider.on('authorization_code.destroyed', tokenDestroySpy);

      this.code.consumed = epochTime();

      return this.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          expect(grantRevokeSpy.calledOnce).to.be.true;
          expect(tokenDestroySpy.calledOnce).to.be.true;
          expect(grantErrorSpy.calledOnce).to.be.true;
          expect(errorDetail(grantErrorSpy)).to.equal('authorization code already consumed');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('consumes the code', function () {
      return this.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(() => {
          expect(this.code).to.have.property('consumed').and.be.most(epochTime());
        })
        .expect(200);
    });

    it('validates code belongs to client', function () {
      const spy = sinon.spy();
      this.provider.on('grant.error', spy);

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb3',
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

    it('validates a grant type is supported', function () {
      return this.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: this.ac,
          grant_type: 'foobar',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'unsupported_grant_type');
        });
    });

    it('validates used redirect_uri (should it be provided)', function () {
      const spy = sinon.spy();
      this.provider.on('grant.error', spy);

      return this.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb?thensome',
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
      sinon.stub(this.provider.Account, 'findAccount').callsFake(() => Promise.resolve());

      const spy = sinon.spy();
      this.provider.on('grant.error', spy);

      return this.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: this.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(() => {
          this.provider.Account.findAccount.restore();
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
    it('grant_type presence', function () {
      return this.agent.post(route)
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

    it('code presence', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          redirect_uri: 'blah',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_request');
          expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
          expect(response.body).to.have.property('error_description').and.matches(/code/);
        });
    });

    it('redirect_uri presence (more then one registered)', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          code: 'blah',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_request');
          expect(response.body).to.have.property('error_description').and.matches(/missing required parameter/);
          expect(response.body).to.have.property('error_description').and.matches(/redirect_uri/);
        });
    });

    it('code being "found"', function () {
      const spy = sinon.spy();
      this.provider.on('grant.error', spy);
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          redirect_uri: 'http://client.example.com',
          code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw',
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
  });

  describe('error handling', () => {
    before(function () {
      sinon.stub(this.provider.Client, 'find').callsFake(async () => { throw new Error(); });
    });
    after(sinon.restore);

    it('handles exceptions', function () {
      const spy = sinon.spy();
      this.provider.on('server_error', spy);

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          code: 'code',
          redirect_uri: 'is there too',
        })
        .type('form')
        .expect(500)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'server_error');
          expect(response.body).to.have.property('error_description', 'oops! something went wrong');
        });
    });
  });
});
