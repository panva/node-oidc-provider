import { describe, before, after, it } from 'node:test';
import assert from 'node:assert/strict';

import bootstrap from '../../test_helper.js';

const route = '/auth';
const response_type = 'none';
const scope = 'openid';
['get', 'post'].forEach((verb) => {
  describe(`${verb} ${route} response_type=none`, () => {
    const fixture = {};

    before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

    before(() => fixture.login(), { timeout: 3000 });
    after(() => fixture.logout(), { timeout: 3000 });

    it('responds with a state in search', { timeout: 3000 }, () => {
      const auth = new fixture.AuthorizationRequest({
        response_type,
        scope,
      });

      return fixture.wrap({ route, verb, auth })
        .expect(303)
        .expect(auth.validatePresence(['state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
    });

    it('responds with a state in fragment', { timeout: 3000 }, () => {
      const auth = new fixture.AuthorizationRequest({
        response_type,
        response_mode: 'fragment',
        scope,
      });

      return fixture.wrap({ route, verb, auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
    });

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      fixture.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Grant', 'Account', 'Session']));
      }, done);

      const auth = new fixture.AuthorizationRequest({
        response_type,
        scope,
      });

      fixture.wrap({ route, verb, auth }).end(() => {});
    });
  });
});
