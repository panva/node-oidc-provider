import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';

import sinon from 'sinon';
import { decodeJwt } from 'jose';

import bootstrap from '../test_helper.js';

describe('responds with a id_token containing auth_time', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  before(() => fixture.login(), { timeout: 3000 });

  const response_type = 'id_token';
  const scope = 'openid';

  it('when max_age was present in the request', { timeout: 3000 }, async () => {
    const auth = new fixture.AuthorizationRequest({
      response_type,
      scope,
      max_age: 999,
    });

    let id_token;

    await fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location, true));
      });

    assert.ok('auth_time' in Object(decodeJwt(id_token)));
  });

  describe('special cases', () => {
    const fixture1 = Object.create(fixture);

    const sandbox = sinon.createSandbox();

    before(() => {
      sandbox.stub(fixture1.provider.OIDCContext.prototype, 'promptPending').returns(false);
    }, { timeout: 3000 });

    after(() => sandbox.restore(), { timeout: 3000 });

    it('when prompt=login was requested', { timeout: 3000 }, async () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type,
        scope,
        prompt: 'login',
      });

      let id_token;

      await fixture1.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          ({ query: { id_token } } = url.parse(response.headers.location, true));
        });

      assert.ok('auth_time' in Object(decodeJwt(id_token)));
    });

    it('when max_age=0 was requested', { timeout: 3000 }, async () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type,
        scope,
        max_age: 0,
      });

      let id_token;

      await fixture1.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          ({ query: { id_token } } = url.parse(response.headers.location, true));
        });

      assert.ok('auth_time' in Object(decodeJwt(id_token)));
    });

    it('when client has default_max_age=0', { timeout: 3000 }, async () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type,
        scope,
        client_id: 'client-with-default_max_age-zero',
      });

      let id_token;

      await fixture1.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          ({ query: { id_token } } = url.parse(response.headers.location, true));
        });

      assert.ok('auth_time' in Object(decodeJwt(id_token)));
    });
  });

  it('when client has require_auth_time', { timeout: 3000 }, async () => {
    const auth = new fixture.AuthorizationRequest({
      response_type,
      scope,
      client_id: 'client-with-require_auth_time',
    });

    let id_token;

    await fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location, true));
      });

    assert.ok('auth_time' in Object(decodeJwt(id_token)));
  });

  it('when client has default_max_age', { timeout: 3000 }, async () => {
    const auth = new fixture.AuthorizationRequest({
      response_type,
      scope,
      client_id: 'client-with-default_max_age',
    });

    let id_token;

    await fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location, true));
      });

    assert.ok('auth_time' in Object(decodeJwt(id_token)));
  });
});
