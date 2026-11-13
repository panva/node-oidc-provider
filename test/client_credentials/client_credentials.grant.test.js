import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

const route = '/token';

describe('grant_type=client_credentials', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  it('provides a Bearer client credentials token', { timeout: 3000 }, () => {
    const spy = sinon.spy();
    fixture.provider.once('grant.success', spy);

    return fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
      })
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'expires_in', 'token_type', 'scope']));
      });
  });

  it('ignores unsupported scopes', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture.provider.once('client_credentials.saved', spy);
    fixture.provider.once('client_credentials.issued', spy);

    await fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:admin',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
      })
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'expires_in', 'token_type', 'scope']));
      });

    const [[token]] = spy.args;

    ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'api:read'); })(token);
  });

  it('returns unauthorized_client when the authenticated client cannot use the grant', { timeout: 3000 }, async () => {
    const client = await fixture.provider.Client.find('client');
    const original = client.grantTypes;
    client.grantTypes = ['authorization_code'];

    try {
      await fixture.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({ grant_type: 'client_credentials', scope: 'api:read' })
        .expect(400)
        .expect({
          error: 'unauthorized_client',
          error_description: 'requested grant type is not allowed for this client',
        });
    } finally {
      client.grantTypes = original;
    }
  });

  it('checks clients scope allow list', { timeout: 3000 }, async () => fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:write',
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_scope',
        error_description: 'requested scope is not allowed',
        scope: 'api:write',
      }));

  it('rejects scope values outside the scope-token grammar', { timeout: 3000 }, () => fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read\ninjected',
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_scope',
        error_description: 'scope contains invalid characters',
      }));

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
