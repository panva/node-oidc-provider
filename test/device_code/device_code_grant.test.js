const { expect } = require('chai');
const sinon = require('sinon');
const base64url = require('base64url');

const bootstrap = require('../test_helper');
const epochTime = require('../../lib/helpers/epoch_time');

const route = '/token';
const grant_type = 'urn:ietf:params:oauth:grant-type:device_code';

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('grant_type=urn:ietf:params:oauth:grant-type:device_code w/ conformIdTokenClaims=false', () => {
  before(bootstrap(__dirname, { config: 'device_code_non_conform' })); // agent

  it('returns the right stuff', async function () {
    const spy = sinon.spy();
    this.provider.once('grant.success', spy);

    const deviceCode = new this.provider.DeviceCode({
      accountId: 'sub',
      scope: 'openid profile offline_access',
      clientId: 'client',
    });
    const code = await deviceCode.save();

    return this.agent.post('/token')
      .type('form')
      .send({
        client_id: 'client',
        device_code: code,
        grant_type,
      })
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'scope', 'refresh_token');
        expect(JSON.parse(base64url.decode(response.body.id_token.split('.')[1]))).to.have.property('given_name');
      });
  });
});

describe('grant_type=urn:ietf:params:oauth:grant-type:device_code', () => {
  before(bootstrap(__dirname));

  it('returns the right stuff', async function () {
    const spy = sinon.spy();
    this.provider.once('grant.success', spy);

    const deviceCode = new this.provider.DeviceCode({
      accountId: 'sub',
      scope: 'openid profile offline_access',
      clientId: 'client',
    });
    const code = await deviceCode.save();

    return this.agent.post('/token')
      .type('form')
      .send({
        client_id: 'client',
        device_code: code,
        grant_type,
      })
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'id_token', 'expires_in', 'token_type', 'scope', 'refresh_token');
        expect(JSON.parse(base64url.decode(response.body.id_token.split('.')[1]))).not.to.have.property('given_name');
      });
  });

  it('populates ctx.oidc.entities (no offline_access)', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.body.refresh_token).to.be.undefined;
      expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'DeviceCode', 'AccessToken');
      expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'device_code');
    }, done));

    const deviceCode = new this.provider.DeviceCode({
      accountId: 'sub',
      scope: 'openid',
      clientId: 'client',
    });
    deviceCode.save().then((code) => {
      this.agent.post(route)
        .type('form')
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .end(() => {});
    });
  });

  it('populates ctx.oidc.entities (w/ offline_access)', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Account', 'Client', 'DeviceCode', 'AccessToken', 'RefreshToken');
      expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'device_code');
      expect(ctx.oidc.entities.RefreshToken).to.have.property('gty', 'device_code');
    }, done));

    const deviceCode = new this.provider.DeviceCode({
      accountId: 'sub',
      scope: 'openid offline_access',
      clientId: 'client',
    });
    deviceCode.save().then((code) => {
      this.agent.post(route)
        .type('form')
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .end(() => {});
    });
  });

  describe('validates', () => {
    it('device_code param presence', function () {
      return this.agent.post(route)
        .send({
          client_id: 'client',
          grant_type,
        })
        .type('form')
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'invalid_request',
          error_description: "missing required parameter 'device_code'",
        });
    });

    it('code being "found"', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return this.agent.post(route)
        .send({
          client_id: 'client',
          grant_type,
          device_code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('device code not found');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('validates account is still there', async function () {
      sinon.stub(this.provider.Account, 'findAccount').callsFake(() => Promise.resolve());

      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const deviceCode = new this.provider.DeviceCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
      });
      const code = await deviceCode.save();

      return this.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(() => {
          this.provider.Account.findAccount.restore();
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('device code invalid (referenced account not found)');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('code belongs to client', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const deviceCode = new this.provider.DeviceCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client-other',
      });
      const code = await deviceCode.save();

      return this.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('device code client mismatch');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    context('', () => {
      before(function () {
        const ttl = i(this.provider).configuration('ttl');
        this.prev = ttl.DeviceCode;
        ttl.DeviceCode = 0;
      });

      after(function () {
        i(this.provider).configuration('ttl').DeviceCode = this.prev;
      });

      it('validates code is not expired', async function () {
        const deviceCode = new this.provider.DeviceCode({
          scope: 'openid',
          clientId: 'client',
        });
        const code = await deviceCode.save();

        return this.agent.post(route)
          .send({
            client_id: 'client',
            device_code: code,
            grant_type,
          })
          .type('form')
          .expect(400)
          .expect({
            error: 'expired_token',
            error_description: 'device code is expired',
          });
      });
    });

    it('consumes the code', async function () {
      const deviceCode = new this.provider.DeviceCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
      });
      const code = await deviceCode.save();

      return this.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(200)
        .expect(() => {
          const jti = this.getTokenJti(code);
          const stored = this.TestAdapter.for('DeviceCode').syncFind(jti);
          expect(stored).to.have.property('consumed').and.be.most(epochTime());
        });
    });

    it('validates code is not already used', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const deviceCode = new this.provider.DeviceCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
      });
      const code = await deviceCode.save();
      await deviceCode.consume();

      return this.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('device code already consumed');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });
  });

  it('responds with authorization_pending if interactions are still pending resolving', async function () {
    const deviceCode = new this.provider.DeviceCode({
      scope: 'openid',
      clientId: 'client',
      // error: missing
      // accountId: missing
    });
    const code = await deviceCode.save();

    return this.agent.post(route)
      .send({
        client_id: 'client',
        device_code: code,
        grant_type,
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'authorization_pending',
        error_description: 'authorization request is still pending as the end-user hasn\'t yet completed the user interaction steps',
      });
  });

  it('responds with a custom error if one is resolved with', async function () {
    const deviceCode = new this.provider.DeviceCode({
      scope: 'openid',
      clientId: 'client',
      error: 'foo',
      errorDescription: 'bar',
    });
    const code = await deviceCode.save();

    return this.agent.post(route)
      .send({
        client_id: 'client',
        device_code: code,
        grant_type,
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'foo',
        error_description: 'bar',
      });
  });

  it('responds with a built-in error if one is resolved with', async function () {
    const spy = sinon.spy();
    this.provider.once('grant.error', spy);

    const deviceCode = new this.provider.DeviceCode({
      scope: 'openid',
      clientId: 'client',
      error: 'access_denied',
      errorDescription: 'user has denied access',
    });
    const code = await deviceCode.save();

    return this.agent.post(route)
      .send({
        client_id: 'client',
        device_code: code,
        grant_type,
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'access_denied',
        error_description: 'user has denied access',
      })
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      });
  });
});
