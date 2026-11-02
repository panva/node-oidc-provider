import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';

import bootstrap from '../test_helper.js';
import { InvalidRequest } from '../../lib/helpers/errors.js';

const sinon = createSandbox();

const route = '/.well-known/openid-configuration';

describe(route, () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  it('responds with json 200', { timeout: 3000 }, () => fixture.agent.get(route)
      .expect('Content-Type', /application\/json/)
      .expect(200));

  it('does not populate ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
    fixture.assertOnce((ctx) => {
      assert.equal(Object.keys(ctx.oidc.entities).length, 0);
    }, done);

    fixture.agent.get(route).end(() => {});
  });

  it('is configurable with extra properties', { timeout: 3000 }, () => {
    i(fixture.provider).configuration.discovery.service_documentation = 'https://docs.example.com';
    i(fixture.provider).configuration.discovery.authorization_endpoint = 'this will not be used';

    return fixture.agent.get(route)
      .expect((response) => {
        ((actual) => { assert.ok('service_documentation' in Object(actual)); assert.equal(actual.service_documentation, 'https://docs.example.com'); })(response.body);
        assert.notEqual(response.body.authorization_endpoint, 'this will not be used');
      });
  });

  describe('with errors', () => {
    const fixture1 = Object.create(fixture);

    before(() => {
      sinon.stub(fixture1.provider, 'pathFor').throws(new InvalidRequest());
    }, { timeout: 3000 });

    after(() => sinon.restore(), { timeout: 3000 });

    it('handles errors with json and corresponding status', { timeout: 3000 }, () => fixture1.agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(400));

    it('emits discovery.error on errors', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.once('discovery.error', spy);

      return fixture1.agent.get(route)
        .expect(() => {
          assert.equal(spy.called, true);
        });
    });
  });

  describe('with exceptions', () => {
    const fixture2 = Object.create(fixture);

    before(() => {
      sinon.stub(fixture2.provider, 'pathFor').throws();
    }, { timeout: 3000 });

    after(() => sinon.restore(), { timeout: 3000 });

    it('handles exceptions with json 500', { timeout: 3000 }, () => fixture2.agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(500)
        .expect({
          error: 'server_error',
          error_description: 'oops! something went wrong',
        }));

    it('emits server_error on exceptions', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture2.provider.once('server_error', spy);

      return fixture2.agent.get(route)
        .expect(() => {
          assert.equal(spy.called, true);
        });
    });
  });
});
