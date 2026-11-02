import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import * as querystring from 'node:querystring';


import bootstrap from '../test_helper.js';

function register(provider, grantType, params, options) {
  provider.registerGrantType(grantType, (ctx) => {
    ctx.body = { winner: ctx.oidc.params.name };
  }, params, options);
}

describe('custom token endpoint grant types', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  before(() => {
    register(fixture.provider, 'lotto', 'name');
    assert.equal(i(fixture.provider).configuration.grantTypes.has('lotto'), true);
  }, { timeout: 3000 });

  it('does not need to be passed extra parameters', { timeout: 3000 }, () => {
    register(fixture.provider, 'lotto-2');
    assert.equal(i(fixture.provider).configuration.grantTypes.has('lotto-2'), true);
  });

  it('can be passed null or a string', { timeout: 3000 }, () => {
    register(fixture.provider, 'lotto-3', null);
    register(fixture.provider, 'lotto-4', 'name');

    assert.equal(i(fixture.provider).configuration.grantTypes.has('lotto-3'), true);
    assert.equal(i(fixture.provider).configuration.grantTypes.has('lotto-4'), true);
  });

  describe('when added', () => {
    const fixture1 = Object.create(fixture);

    before(async () => {
      const client = await fixture1.provider.Client.find('client');
      client.grantTypes.push('lotto');
    }, { timeout: 3000 });

    describe('rejectDupes behavior', () => {
      const fixture2 = Object.create(fixture1);

      const data = `${querystring.stringify({ grant_type: 'lotto', name: 'John Doe' })}&name=FooBar`;
      it('by default reject dupes', { timeout: 3000 }, () => fixture2.agent.post('/token')
          .auth('client', 'secret')
          .send(data)
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: "'name' parameter must not be provided twice",
          }));

      // see OAuth 2.0 Token Exchange - audience and resource
      it('can be exempt params from being dupe-checked', { timeout: 3000 }, () => {
        register(fixture2.provider, 'lotto', 'name', ['name']);
        return fixture2.agent.post('/token')
          .auth('client', 'secret')
          .send(data)
          .type('form')
          .expect(200)
          .expect({ winner: ['John Doe', 'FooBar'] });
      });

      it('can be exempt params from being dupe-checked but still checks other params', { timeout: 3000 }, () => {
        register(fixture2.provider, 'lotto', new Set(['name', 'foo']), new Set(['name']));
        return fixture2.agent.post('/token')
          .auth('client', 'secret')
          .send(`${data}&foo=bar&foo=bar`)
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: "'foo' parameter must not be provided twice",
          });
      });

      it('can be exempt params from being dupe-checked (except for grant_type)', { timeout: 3000 }, () => {
        register(fixture2.provider, 'lotto', 'name', 'name');
        return fixture2.agent.post('/token')
          .auth('client', 'secret')
          .send(`${data}&grant_type=lotto`)
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: "'grant_type' parameter must not be provided twice",
          });
      });
    });

    it('clients can start using it', { timeout: 3000 }, () => fixture1.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'lotto', name: 'John Doe' })
        .type('form')
        .expect(200)
        .expect({ winner: 'John Doe' }));

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      fixture1.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client']));
      }, done);

      fixture1.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'lotto', name: 'John Doe' })
        .type('form')
        .end(() => {});
    });
  });
});
