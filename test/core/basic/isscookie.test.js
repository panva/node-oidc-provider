import bootstrap from '../../test_helper.js';

describe('pre-middleware setting "set-cookie" header', () => {
  before(bootstrap(import.meta.url));

  before(function () {
    this.provider.use((ctx, next) => {
      ctx.set('set-cookie', 'foo=bar;');
      return next();
    });
  });

  it('does not disturb the session middleware', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'invalid',
      state: null,
    });

    return this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(auth.validatePresence(['error', 'error_description']));
  });
});
