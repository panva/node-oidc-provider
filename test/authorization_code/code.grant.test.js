import { describe, before, afterEach, beforeEach, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseUrl } from 'node:url';

import { createSandbox } from 'sinon';
import timekeeper from 'timekeeper';

import epochTime from '../../lib/helpers/epoch_time.js';
import bootstrap from '../test_helper.js';

const sinon = createSandbox();

const route = '/token';

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('grant_type=authorization_code', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => timekeeper.reset(), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  afterEach(() => {
    fixture.provider.removeAllListeners('grant.success');
    fixture.provider.removeAllListeners('grant.error');
    fixture.provider.removeAllListeners('server_error');
  }, { timeout: 3000 });

  describe('with real tokens (1/3) - more than one redirect_uris registered', () => {
    const fixture1 = Object.create(fixture);

    beforeEach(() => fixture1.login(), { timeout: 3000 });
    afterEach(() => fixture1.logout(), { timeout: 3000 });

    beforeEach(() => fixture1.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(303)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = fixture1.getTokenJti(code);
          fixture1.code = fixture1.TestAdapter.for('AuthorizationCode').syncFind(jti);
          fixture1.ac = code;
        }), { timeout: 3000 });

    it('returns the right stuff', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.on('grant.success', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        })
        .expect((response) => {
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'scope']));
          assert.notDeepEqual(new Set(Object.keys(response.body)), new Set(['refresh_token']));
        });
    });

    it('populates ctx.oidc.entities (no offline_access)', { timeout: 3000 }, (_t, done) => {
      fixture1.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AuthorizationCode', 'AccessToken']));
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.AccessToken);
      }, done);

      fixture1.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .end(() => {});
    });

    it('preserves token issuance callback order and entity availability', { timeout: 3000 }, async () => {
      const calls = [];
      const configuration = i(fixture1.provider).configuration;

      sinon.stub(configuration, 'findAccount').callsFake((ctx, accountId, source) => {
        calls.push('findAccount');
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'AuthorizationCode', 'Grant']));
        assert.equal(source, ctx.oidc.entities.AuthorizationCode);
        assert.equal(typeof fixture1.TestAdapter.for('AuthorizationCode').syncFind(source.jti).consumed, 'number');

        return {
          accountId,
          claims() {
            calls.push('claims');
            assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'AuthorizationCode', 'Grant', 'Account', 'AccessToken', 'RefreshToken']));
            return { sub: accountId };
          },
        };
      });
      sinon.stub(configuration, 'issueRefreshToken').callsFake((ctx, client, source) => {
        calls.push('issueRefreshToken');
        assert.equal(client, ctx.oidc.client);
        assert.equal(source, ctx.oidc.entities.AuthorizationCode);
        assert.ok('AccessToken' in Object(ctx.oidc.entities));
        assert.ok(!('RefreshToken' in Object(ctx.oidc.entities)));
        return true;
      });
      fixture1.provider.once('access_token.saved', () => calls.push('access_token.saved'));
      fixture1.provider.once('refresh_token.saved', () => calls.push('refresh_token.saved'));

      await fixture1.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200);

      assert.deepEqual(calls, [
        'findAccount', 'access_token.saved', 'issueRefreshToken', 'refresh_token.saved', 'claims',
      ]);
    });

    it('populates ctx.oidc.entities (w/ offline_access)', { timeout: 3000 }, (_t, done) => {
      fixture1.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AuthorizationCode', 'AccessToken', 'RefreshToken']));
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.AccessToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.RefreshToken);
      }, done);

      fixture1.TestAdapter.for('Grant').syncUpdate(fixture1.getSession().authorizations.client.grantId, {
        scope: 'openid offline_access',
      });
      fixture1.TestAdapter.for('AuthorizationCode').syncUpdate(fixture1.getTokenJti(fixture1.ac), {
        scope: 'openid offline_access',
      });
      fixture1.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .end(() => {});
    });

    it('returns token-endpoint-like cache headers', { timeout: 3000 }, () => fixture1.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect('cache-control', 'no-store'));

    describe('', () => {
      const fixture2 = Object.create(fixture1);

      before(() => {
        const { ttl } = i(fixture2.provider).configuration;
        fixture2.prev = ttl.AuthorizationCode;
        ttl.AuthorizationCode = 5;
      }, { timeout: 3000 });

      after(() => {
        i(fixture2.provider).configuration.ttl.AuthorizationCode = fixture2.prev;
      }, { timeout: 3000 });

      it('validates code is not expired', { timeout: 3000 }, () => {
        timekeeper.travel(Date.now() + (10 * 1000));
        const spy = sinon.spy();
        fixture2.provider.on('grant.error', spy);

        return fixture2.agent.post(route)
          .auth('client', 'secret')
          .send({
            code: fixture2.ac,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .expect(400)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'authorization code is expired');
          })
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          });
      });
    });

    it('validates code is not already used', { timeout: 3000 }, () => {
      const grantErrorSpy = sinon.spy();
      const grantRevokeSpy = sinon.spy();
      fixture1.provider.on('grant.error', grantErrorSpy);
      fixture1.provider.on('grant.revoked', grantRevokeSpy);

      fixture1.code.consumed = epochTime();

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(grantRevokeSpy.calledOnce, true);
          assert.equal(grantErrorSpy.calledOnce, true);
          assert.equal(errorDetail(grantErrorSpy), 'authorization code already consumed');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('consumes the code', { timeout: 3000 }, () => fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(() => {
          ((actual) => { assert.ok('consumed' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(value <= epochTime()); })(actual.consumed); })(fixture1.code);
        })
        .expect(200));

    it('validates code belongs to client', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.on('grant.error', spy);

      return fixture1.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
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

    it('validates a grant type is supported', { timeout: 3000 }, () => fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture1.ac,
          grant_type: 'foobar',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'unsupported_grant_type'); })(response.body);
        }));

    it('validates used redirect_uri', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.on('grant.error', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb?thensome',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'authorization code redirect_uri mismatch');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('validates redirect_uri presence', { timeout: 3000 }, () => fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "missing required parameter 'redirect_uri'"); })(response.body);
        }));

    it('validates account is still there', { timeout: 3000 }, () => {
      sinon.stub(i(fixture1.provider).configuration, 'findAccount').callsFake(() => Promise.resolve());

      const spy = sinon.spy();
      fixture1.provider.on('grant.error', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture1.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'authorization code invalid (referenced account not found)');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });
  });

  describe('with real tokens (2/3) - one redirect_uri registered with allowOmittingSingleRegisteredRedirectUri=false', () => {
    const fixture3 = Object.create(fixture);

    beforeEach(async () => {
      await fixture3.login();
      return fixture3.agent.get('/auth')
        .query({
          client_id: 'client2',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb3',
        })
        .expect(303)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          fixture3.ac = code;
        });
    }, { timeout: 3000 });

    it('validates redirect_uri presence', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture3.provider.on('grant.error', spy);

      return fixture3.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture3.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "missing required parameter 'redirect_uri'"); })(response.body);
        });
    });
  });

  describe('with real tokens (3/3) - one redirect_uri registered with allowOmittingSingleRegisteredRedirectUri=true', () => {
    const fixture4 = Object.create(fixture);

    beforeEach(() => {
      i(fixture4.provider).configuration.allowOmittingSingleRegisteredRedirectUri = true;
      return fixture4.login();
    }, { timeout: 3000 });

    afterEach(() => {
      i(fixture4.provider).configuration.allowOmittingSingleRegisteredRedirectUri = false;
      return fixture4.logout();
    }, { timeout: 3000 });

    beforeEach(() => fixture4.agent.get('/auth')
        .query({
          client_id: 'client2',
          scope: 'openid',
          response_type: 'code',
        })
        .expect(303)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = fixture4.getTokenJti(code);
          fixture4.code = fixture4.TestAdapter.for('AuthorizationCode').syncFind(jti);
          fixture4.ac = code;
        }), { timeout: 3000 });

    it('returns the right stuff', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture4.provider.on('grant.success', spy);

      return fixture4.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
        })
        .expect(200)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        })
        .expect((response) => {
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'scope']));
          assert.notDeepEqual(new Set(Object.keys(response.body)), new Set(['refresh_token']));
        });
    });

    it('populates ctx.oidc.entities (no offline_access)', { timeout: 3000 }, (_t, done) => {
      fixture4.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AuthorizationCode', 'AccessToken']));
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.AccessToken);
      }, done);

      fixture4.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
        })
        .end(() => {});
    });

    it('populates ctx.oidc.entities (w/ offline_access)', { timeout: 3000 }, (_t, done) => {
      fixture4.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AuthorizationCode', 'AccessToken', 'RefreshToken']));
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.AccessToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.RefreshToken);
      }, done);

      fixture4.TestAdapter.for('Grant').syncUpdate(fixture4.getSession().authorizations.client2.grantId, {
        scope: 'openid offline_access',
      });
      fixture4.TestAdapter.for('AuthorizationCode').syncUpdate(fixture4.getTokenJti(fixture4.ac), {
        scope: 'openid offline_access',
      });
      fixture4.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
        })
        .end(() => {});
    });

    it('returns token-endpoint-like cache headers', { timeout: 3000 }, () => fixture4.agent.post(route)
        .auth('client2', 'secret')
        .type('form')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
        })
        .expect('cache-control', 'no-store'));

    describe('', () => {
      const fixture5 = Object.create(fixture4);

      before(() => {
        const { ttl } = i(fixture5.provider).configuration;
        fixture5.prev = ttl.AuthorizationCode;
        ttl.AuthorizationCode = 5;
      }, { timeout: 3000 });

      after(() => {
        i(fixture5.provider).configuration.ttl.AuthorizationCode = fixture5.prev;
      }, { timeout: 3000 });

      it('validates code is not expired', { timeout: 3000 }, () => {
        timekeeper.travel(Date.now() + (10 * 1000));
        const spy = sinon.spy();
        fixture5.provider.on('grant.error', spy);

        return fixture5.agent.post(route)
          .auth('client2', 'secret')
          .send({
            code: fixture5.ac,
            grant_type: 'authorization_code',
          })
          .type('form')
          .expect(400)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'authorization code is expired');
          })
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          });
      });
    });

    it('validates code is not already used', { timeout: 3000 }, () => {
      const grantErrorSpy = sinon.spy();
      const grantRevokeSpy = sinon.spy();
      fixture4.provider.on('grant.error', grantErrorSpy);
      fixture4.provider.on('grant.revoked', grantRevokeSpy);

      fixture4.code.consumed = epochTime();

      return fixture4.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(grantRevokeSpy.calledOnce, true);
          assert.equal(grantErrorSpy.calledOnce, true);
          assert.equal(errorDetail(grantErrorSpy), 'authorization code already consumed');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('consumes the code', { timeout: 3000 }, () => fixture4.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(() => {
          ((actual) => { assert.ok('consumed' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(value <= epochTime()); })(actual.consumed); })(fixture4.code);
        })
        .expect(200));

    it('validates code belongs to client', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture4.provider.on('grant.error', spy);

      return fixture4.agent.post(route)
        .auth('client', 'secret')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb3',
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

    it('validates a grant type is supported', { timeout: 3000 }, () => fixture4.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: fixture4.ac,
          grant_type: 'foobar',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'unsupported_grant_type'); })(response.body);
        }));

    it('validates used redirect_uri (should it be provided)', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture4.provider.on('grant.error', spy);

      return fixture4.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb?thensome',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'authorization code redirect_uri mismatch');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('validates account is still there', { timeout: 3000 }, () => {
      sinon.stub(i(fixture4.provider).configuration, 'findAccount').callsFake(() => Promise.resolve());

      const spy = sinon.spy();
      fixture4.provider.on('grant.error', spy);

      return fixture4.agent.post(route)
        .auth('client2', 'secret')
        .send({
          code: fixture4.ac,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'authorization code invalid (referenced account not found)');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });
  });

  describe('validates', () => {
    const fixture6 = Object.create(fixture);

    it('grant_type presence', { timeout: 3000 }, () => fixture6.agent.post(route)
        .auth('client', 'secret')
        .send({})
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /missing required parameter/); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /grant_type/); })(response.body);
        }));

    it('code presence', { timeout: 3000 }, () => fixture6.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          redirect_uri: 'blah',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /missing required parameter/); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /code/); })(response.body);
        }));

    it('redirect_uri presence (more then one registered)', { timeout: 3000 }, () => fixture6.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          code: 'blah',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /missing required parameter/); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /redirect_uri/); })(response.body);
        }));

    it('code being "found"', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture6.provider.on('grant.error', spy);
      return fixture6.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          redirect_uri: 'http://client.example.com',
          code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'authorization code not found');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });
  });

  describe('error handling', () => {
    const fixture7 = Object.create(fixture);

    before(() => {
      sinon.stub(fixture7.provider.Client, 'find').callsFake(async () => { throw new Error(); });
    }, { timeout: 3000 });

    it('handles exceptions', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture7.provider.on('server_error', spy);

      return fixture7.agent.post(route)
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          code: 'code',
          redirect_uri: 'is there too',
        })
        .type('form')
        .expect(500)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'server_error'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'oops! something went wrong'); })(response.body);
        });
    });
  });
});
