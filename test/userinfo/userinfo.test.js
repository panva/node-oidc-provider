import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';

import sinon from 'sinon';

import Provider from '../../lib/index.js';
import bootstrap from '../test_helper.js';

describe('userinfo /me', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  before(() => fixture.login({ scope: 'openid email', rejectedClaims: ['email_verified'] }), { timeout: 3000 });

  before(() => {
    const auth = new fixture.AuthorizationRequest({
      response_type: 'id_token token',
      scope: 'openid email',
    });

    return fixture.wrap({ auth, verb: 'get', route: '/auth' })
      .expect(auth.validateFragment)
      .expect((response) => {
        const { query } = url.parse(response.headers.location, true);
        fixture.access_token = query.access_token;
      });
  }, { timeout: 3000 });

  it('jwtUserinfo can only be enabled with userinfo', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('http://localhost', {
        features: {
          jwtUserinfo: { enabled: true },
          userinfo: { enabled: false },
        },
      });
    }, (error) => { assert.ok(error.message.includes('jwtUserinfo is only available in conjunction with userinfo')); return true; });
  });

  it('[get] returns 200 OK and user claims except the rejected ones', { timeout: 3000 }, () => fixture.agent.get('/me')
      .auth(fixture.access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['sub', 'email']));
        assert.notDeepEqual(new Set(Object.keys(response.body)), new Set(['email_verified']));
      }));

  it('[post] returns 200 OK and user claims except the rejected ones', { timeout: 3000 }, () => fixture.agent.post('/me')
      .auth(fixture.access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['sub', 'email']));
        assert.notDeepEqual(new Set(Object.keys(response.body)), new Set(['email_verified']));
      }));

  it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
    fixture.assertOnce((ctx) => {
      assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Grant', 'AccessToken', 'Account']));
      assert.deepEqual(Object.keys(ctx.oidc.entities), [
        'AccessToken',
        'Client',
        'Account',
        'Grant',
      ]);
    }, done);

    (async () => {
      await fixture.agent.get('/me').auth(fixture.access_token, { type: 'bearer' });
    })().catch(done);
  });

  it('validates access token is found', { timeout: 3000 }, () => fixture.agent.get('/me')
      .auth('Loremipsumdolorsitametconsecteturadipisicingelitsed', { type: 'bearer' })
      .expect(fixture.failWith(401, 'invalid_token', 'invalid token provided')));

  it('validates access token is provided', { timeout: 3000 }, () => fixture.agent.get('/me')
      .expect(fixture.failWith(401, 'invalid_token', 'no access token provided')));

  it('validates the openid scope is present', { timeout: 3000 }, async () => {
    const at = await new fixture.provider.AccessToken({
      client: await fixture.provider.Client.find('client'),
    }).save();
    sinon.stub(fixture.provider.Client, 'find').callsFake(async () => undefined);
    return fixture.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(() => {
        fixture.provider.Client.find.restore();
      })
      .expect(fixture.failWith(403, 'insufficient_scope', 'access token missing openid scope', 'openid'));
  });

  it('validates a client is still valid for a found token', { timeout: 3000 }, async () => {
    const at = await new fixture.provider.AccessToken({
      client: await fixture.provider.Client.find('client'),
      scope: 'openid',
    }).save();
    const find = sinon.stub(fixture.provider.Client, 'find').resolves();
    const spy = sinon.spy();
    fixture.provider.once('userinfo.error', spy);

    try {
      await fixture.agent.get('/me')
        .auth(at, { type: 'bearer' })
        .expect(fixture.failWith(401, 'invalid_token', 'invalid token provided'));
    } finally {
      find.restore();
    }

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
    ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'associated client not found'); })(spy.args[0][1]);
    assert.deepEqual(Object.keys(spy.args[0][0].oidc.entities), ['AccessToken']);
  });

  it('validates an account still valid for a found token', { timeout: 3000 }, async () => {
    const at = await new fixture.provider.AccessToken({
      client: await fixture.provider.Client.find('client'),
      scope: 'openid',
      accountId: 'notfound',
    }).save();
    const spy = sinon.spy();
    fixture.provider.once('userinfo.error', spy);

    await fixture.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(fixture.failWith(401, 'invalid_token', 'invalid token provided'));

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
    ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'associated account not found'); })(spy.args[0][1]);
    assert.deepEqual(Object.keys(spy.args[0][0].oidc.entities), [
      'AccessToken',
      'Client',
    ]);
  });

  for (const { title, getGrant, errorDetail } of [
    {
      title: 'validates the associated grant is found',
      getGrant() {},
      errorDetail: 'grant not found',
    },
    {
      title: 'validates the associated grant is not expired',
      getGrant(accessToken) {
        return {
          isExpired: true,
          clientId: accessToken.clientId,
          accountId: accessToken.accountId,
        };
      },
      errorDetail: 'grant is expired',
    },
    {
      title: 'validates the associated grant belongs to the client',
      getGrant(accessToken) {
        return {
          isExpired: false,
          clientId: 'another-client',
          accountId: accessToken.accountId,
        };
      },
      errorDetail: 'clientId mismatch',
    },
    {
      title: 'validates the associated grant belongs to the account',
      getGrant(accessToken) {
        return {
          isExpired: false,
          clientId: accessToken.clientId,
          accountId: 'another-account',
        };
      },
      errorDetail: 'accountId mismatch',
    },
  ]) {
    it(title, { timeout: 3000 }, async () => {
      const accessToken = await fixture.provider.AccessToken.find(fixture.access_token);
      const find = sinon.stub(fixture.provider.Grant, 'find').resolves(getGrant(accessToken));
      const spy = sinon.spy();
      fixture.provider.once('userinfo.error', spy);

      try {
        await fixture.agent.get('/me')
          .auth(fixture.access_token, { type: 'bearer' })
          .expect(fixture.failWith(401, 'invalid_token', 'invalid token provided'));
      } finally {
        find.restore();
      }

      assert.equal(find.calledOnceWithExactly(accessToken.grantId, {
        ignoreExpiration: true,
      }), true);
      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, errorDetail); })(spy.args[0][1]);
      assert.deepEqual(Object.keys(spy.args[0][0].oidc.entities), [
        'AccessToken',
        'Client',
        'Account',
      ]);
    });
  }

  it('does allow for scopes to be shrunk', { timeout: 3000 }, () => fixture.agent.get('/me')
      .query({
        scope: 'openid',
      })
      .auth(fixture.access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['sub']));
        assert.notDeepEqual(new Set(Object.keys(response.body)), new Set(['email', 'email_verified']));
      }));

  it('does not allow for scopes to be extended', { timeout: 3000 }, () => fixture.agent.get('/me')
      .query({
        scope: 'openid profile',
      })
      .auth(fixture.access_token, { type: 'bearer' })
      .expect(fixture.failWith(403, 'insufficient_scope', 'access token missing requested scope', 'profile')));

  it('rejects control characters in a requested scope without failing header serialization', { timeout: 3000 }, () => fixture.agent.get('/me')
      .query({
        scope: 'openid profile\ninjected',
      })
      .auth(fixture.access_token, { type: 'bearer' })
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: 'scope contains invalid characters',
      }));
});
