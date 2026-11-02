import { describe, before, it } from 'node:test';
import bootstrap from '../../test_helper.js';

describe('pre-middleware setting "set-cookie" header', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  before(() => {
    fixture.provider.use((ctx, next) => {
      ctx.set('set-cookie', 'foo=bar;');
      return next();
    });
  }, { timeout: 3000 });

  it('does not disturb the session middleware', { timeout: 3000 }, () => {
    const auth = new fixture.AuthorizationRequest({
      response_type: 'invalid',
      state: null,
    });

    return fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(auth.validatePresence(['error', 'error_description']));
  });
});
