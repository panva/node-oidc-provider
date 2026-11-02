import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import base64url from 'base64url';
import { createSandbox } from 'sinon';
import epochTime from '../../lib/helpers/epoch_time.js';
import bootstrap from '../test_helper.js';

const route = '/token';
const grant_type = 'urn:ietf:params:oauth:grant-type:device_code';

const sinon = createSandbox();

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('grant_type=urn:ietf:params:oauth:grant-type:device_code w/ conformIdTokenClaims=false', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'device_code_non_conform' }), { timeout: 3000 }); // agent
  before(() => fixture.login({ scope: 'openid profile offline_access', accountId: 'sub' }), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  it('returns the right stuff', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture.provider.once('grant.success', spy);

    const deviceCode = new fixture.provider.DeviceCode({
      accountId: 'sub',
      grantId: fixture.getGrantId(),
      scope: 'openid profile offline_access',
      clientId: 'client',
    });
    const code = await deviceCode.save();

    return fixture.agent.post('/token')
      .type('form')
      .send({
        client_id: 'client',
        device_code: code,
        grant_type,
      })
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
      })
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'scope', 'refresh_token']));
        assert.ok('given_name' in Object(JSON.parse(base64url.decode(response.body.id_token.split('.')[1]))));
      });
  });
});

describe('grant_type=urn:ietf:params:oauth:grant-type:device_code', () => {
  const fixture1 = {};

  before(bootstrap(import.meta.url, fixture1), { timeout: 3000 });
  before(() => fixture1.login({ scope: 'openid profile offline_access', accountId: 'sub' }), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  it('returns the right stuff', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture1.provider.once('grant.success', spy);

    const deviceCode = new fixture1.provider.DeviceCode({
      accountId: 'sub',
      grantId: fixture1.getGrantId(),
      scope: 'openid profile offline_access',
      clientId: 'client',
    });
    const code = await deviceCode.save();

    return fixture1.agent.post('/token')
      .type('form')
      .send({
        client_id: 'client',
        device_code: code,
        grant_type,
      })
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
      })
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'scope', 'refresh_token']));
        assert.ok(!('given_name' in Object(JSON.parse(base64url.decode(response.body.id_token.split('.')[1])))));
      });
  });

  it('populates ctx.oidc.entities (no offline_access)', { timeout: 3000 }, (_t, done) => {
    fixture1.assertOnce((ctx) => {
      assert.equal(ctx.body.refresh_token, undefined);
      assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'DeviceCode', 'AccessToken']));
      ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'device_code'); })(ctx.oidc.entities.AccessToken);
    }, done);

    const deviceCode = new fixture1.provider.DeviceCode({
      accountId: 'sub',
      grantId: fixture1.getGrantId(),
      scope: 'openid',
      clientId: 'client',
    });
    deviceCode.save().then((code) => {
      fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .end(() => {});
    });
  });

  it('populates ctx.oidc.entities (w/ offline_access)', { timeout: 3000 }, (_t, done) => {
    fixture1.assertOnce((ctx) => {
      assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'DeviceCode', 'AccessToken', 'RefreshToken']));
      ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'device_code'); })(ctx.oidc.entities.AccessToken);
      ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'device_code'); })(ctx.oidc.entities.RefreshToken);
    }, done);

    const deviceCode = new fixture1.provider.DeviceCode({
      accountId: 'sub',
      grantId: fixture1.getGrantId(),
      scope: 'openid offline_access',
      clientId: 'client',
    });
    deviceCode.save().then((code) => {
      fixture1.agent.post(route)
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
    const fixture2 = Object.create(fixture1);

    it('device_code param presence', { timeout: 3000 }, () => fixture2.agent.post(route)
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
        }));

    it('code being "found"', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture2.provider.once('grant.error', spy);
      return fixture2.agent.post(route)
        .send({
          client_id: 'client',
          grant_type,
          device_code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'device code not found');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('validates account is still there', { timeout: 3000 }, async () => {
      sinon.stub(i(fixture2.provider).configuration, 'findAccount').callsFake(() => Promise.resolve());

      const spy = sinon.spy();
      fixture2.provider.once('grant.error', spy);

      const deviceCode = new fixture2.provider.DeviceCode({
        accountId: 'sub',
        grantId: fixture2.getGrantId(),
        scope: 'openid',
        clientId: 'client',
      });
      const code = await deviceCode.save();

      return fixture2.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'device code invalid (referenced account not found)');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('code belongs to client', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture2.provider.once('grant.error', spy);

      const deviceCode = new fixture2.provider.DeviceCode({
        accountId: 'sub',
        grantId: fixture2.getGrantId(),
        scope: 'openid',
        clientId: 'client-other',
      });
      const code = await deviceCode.save();

      return fixture2.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'client mismatch');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    describe('', () => {
      const fixture3 = Object.create(fixture2);

      it('validates code is not expired', { timeout: 3000 }, async () => {
        const deviceCode = new fixture3.provider.DeviceCode({
          scope: 'openid',
          clientId: 'client',
          expiresIn: -1,
        });
        const code = await deviceCode.save();

        return fixture3.agent.post(route)
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

    it('consumes the code', { timeout: 3000 }, async () => {
      const deviceCode = new fixture2.provider.DeviceCode({
        accountId: 'sub',
        grantId: fixture2.getGrantId(),
        scope: 'openid',
        clientId: 'client',
      });
      const code = await deviceCode.save();

      return fixture2.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(200)
        .expect(() => {
          const jti = fixture2.getTokenJti(code);
          const stored = fixture2.TestAdapter.for('DeviceCode').syncFind(jti);
          ((actual) => { assert.ok('consumed' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(value <= epochTime()); })(actual.consumed); })(stored);
        });
    });

    it('validates code is not already used', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture2.provider.once('grant.error', spy);

      const deviceCode = new fixture2.provider.DeviceCode({
        accountId: 'sub',
        grantId: fixture2.getGrantId(),
        scope: 'openid',
        clientId: 'client',
      });
      const code = await deviceCode.save();
      await deviceCode.consume();

      return fixture2.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'device code already consumed');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('skips grant revocation when an already consumed code has no grantId', { timeout: 3000 }, async () => {
      const deviceCode = new fixture2.provider.DeviceCode({
        scope: 'openid',
        clientId: 'client',
        error: 'access_denied',
        errorDescription: 'user has denied access',
      });
      const code = await deviceCode.save();

      await fixture2.agent.post(route)
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
        });

      const accessTokenRevokeByGrantIdSpy = sinon.spy(fixture2.TestAdapter.for('AccessToken'), 'revokeByGrantId');
      const refreshTokenRevokeByGrantIdSpy = sinon.spy(fixture2.TestAdapter.for('RefreshToken'), 'revokeByGrantId');
      const deviceCodeRevokeByGrantIdSpy = sinon.spy(fixture2.TestAdapter.for('DeviceCode'), 'revokeByGrantId');
      const grantDestroySpy = sinon.spy(fixture2.TestAdapter.for('Grant'), 'destroy');
      const grantErrorSpy = sinon.spy();
      const grantRevokeSpy = sinon.spy();
      fixture2.provider.once('grant.error', grantErrorSpy);
      fixture2.provider.once('grant.revoked', grantRevokeSpy);

      return fixture2.agent.post(route)
        .send({
          client_id: 'client',
          device_code: code,
          grant_type,
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(grantErrorSpy.calledOnce, true);
          assert.equal(errorDetail(grantErrorSpy), 'device code already consumed');
          assert.equal(grantRevokeSpy.called, false);
          assert.equal(accessTokenRevokeByGrantIdSpy.called, false);
          assert.equal(refreshTokenRevokeByGrantIdSpy.called, false);
          assert.equal(deviceCodeRevokeByGrantIdSpy.called, false);
          assert.equal(grantDestroySpy.called, false);
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });
  });

  it('responds with authorization_pending if interactions are still pending resolving', { timeout: 3000 }, async () => {
    const deviceCode = new fixture1.provider.DeviceCode({
      scope: 'openid',
      clientId: 'client',
      // error: missing
      // accountId: missing
    });
    const code = await deviceCode.save();

    return fixture1.agent.post(route)
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

  it('responds with a custom error if one is resolved with', { timeout: 3000 }, async () => {
    const deviceCode = new fixture1.provider.DeviceCode({
      scope: 'openid',
      clientId: 'client',
      error: 'foo',
      errorDescription: 'bar',
    });
    const code = await deviceCode.save();

    return fixture1.agent.post(route)
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

  it('responds with a built-in error if one is resolved with', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture1.provider.once('grant.error', spy);

    const deviceCode = new fixture1.provider.DeviceCode({
      scope: 'openid',
      clientId: 'client',
      error: 'access_denied',
      errorDescription: 'user has denied access',
    });
    const code = await deviceCode.save();

    return fixture1.agent.post(route)
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
        assert.equal(spy.calledOnce, true);
      });
  });
});
