import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

const route = '/token';

describe('grant_type=client_credentials w/ resourceIndicators', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'client_credentials' }), { timeout: 3000 });

  it('provides a Bearer client credentials opaque token', { timeout: 3000 }, () => {
    const spy = sinon.spy();
    fixture.provider.once('client_credentials.saved', spy);

    return fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:wl:opaque',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('scope' in Object(actual)); assert.deepEqual(actual.scope, 'api:read'); })(spy.firstCall.args[0]);
        ((actual) => { assert.ok('aud' in Object(actual)); assert.deepEqual(actual.aud, 'urn:wl:opaque'); })(spy.firstCall.args[0]);
      })
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'expires_in', 'token_type', 'scope']));
        assert.deepEqual(response.body.scope, 'api:read');
      });
  });

  it('provides a Bearer client credentials jwt token', { timeout: 3000 }, () => {
    const spy = sinon.spy();
    fixture.provider.once('client_credentials.issued', spy);

    return fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:wl:jwt',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('scope' in Object(actual)); assert.deepEqual(actual.scope, 'api:read'); })(spy.firstCall.args[0]);
        ((actual) => { assert.ok('aud' in Object(actual)); assert.deepEqual(actual.aud, 'urn:wl:jwt'); })(spy.firstCall.args[0]);
      })
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'expires_in', 'token_type', 'scope']));
        assert.deepEqual(response.body.scope, 'api:read');
      });
  });

  it('ignores unsupported scopes', { timeout: 3000 }, () => fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:admin',
        resource: 'urn:wl',
      })
      .type('form')
      .expect(200)
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'expires_in', 'token_type', 'scope']));
        assert.deepEqual(response.body.scope, 'api:read');
      }));

  it('can reject resource indicator', { timeout: 3000 }, () => fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:admin',
        resource: 'urn:bl',
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_target',
        error_description: 'resource indicator is missing, or unknown',
      }));

  it('only supports a single resource indicator', { timeout: 3000 }, () => fixture.agent.post(route)
      .auth('client', 'secret')
      .send('grant_type=client_credentials&scope=api:read&resource=urn:wl:opaque:default&resource=urn:wl:opaque:explicit')
      .type('form')
      .expect(400)
      .expect(/invalid_target/)
      .expect(/only a single resource indicator value is supported/));

  it('validates each resource to be a valid URI individually', { timeout: 3000 }, () => fixture.agent.post(route)
      .auth('client', 'secret')
      .send('grant_type=client_credentials&scope=api:read&resource=urn:wl:opaque:default&resource=invalid')
      .type('form')
      .expect(400)
      .expect(/invalid_target/)
      .expect(/resource indicator must be an absolute URI/));

  it('checks the policy and adds the resource', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture.provider.once('client_credentials.saved', spy);
    fixture.provider.once('client_credentials.issued', spy);

    await fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:not:allowed',
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_target',
        error_description: 'resource indicator is missing, or unknown',
      });

    await fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:wl:opaque:explicit',
      })
      .type('form')
      .expect(200);

    assert.equal(spy.calledOnce, true);
    const token = spy.args[0][0];
    assert.equal(token.aud, 'urn:wl:opaque:explicit');
    assert.equal(token.scope, 'api:read');
  });

  it('also ignores resource unrecognized scopes', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture.provider.once('client_credentials.saved', spy);
    fixture.provider.once('client_credentials.issued', spy);

    await fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:write unrecognized',
        resource: 'urn:wl:opaque:explicit',
      })
      .type('form')
      .expect(200);

    assert.equal(spy.calledOnce, true);
    const token = spy.args[0][0];
    assert.equal(token.aud, 'urn:wl:opaque:explicit');
    assert.equal(token.scope, 'api:read api:write');
  });

  it('applies the default resource', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture.provider.once('client_credentials.saved', spy);
    fixture.provider.once('client_credentials.issued', spy);

    await fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
      })
      .type('form')
      .expect(200);

    assert.equal(spy.calledOnce, true);
    const token = spy.args[0][0];
    assert.equal(token.aud, 'urn:wl:opaque:default');
  });

  it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
    fixture.assertOnce((ctx) => {
      assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'ClientCredentials']));
    }, done);

    fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
      })
      .type('form')
      .end(() => {});
  });
});
