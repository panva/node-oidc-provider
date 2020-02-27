const { expect } = require('chai');

const bootstrap = require('../../test_helper');

const route = '/auth';
const response_type = 'none';
const scope = 'openid';

['get', 'post'].forEach((verb) => {
  describe(`${verb} ${route} response_type=none`, () => {
    before(bootstrap(__dirname));

    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('responds with a state in search', function () {
      const auth = new this.AuthorizationRequest({
        response_type,
        scope,
      });

      return this.wrap({ route, verb, auth })
        .expect(302)
        .expect(auth.validatePresence(['state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
    });

    it('responds with a state in fragment', function () {
      const auth = new this.AuthorizationRequest({
        response_type,
        response_mode: 'fragment',
        scope,
      });

      return this.wrap({ route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client', 'Account', 'Session');
      }, done));

      const auth = new this.AuthorizationRequest({
        response_type,
        scope,
      });

      this.wrap({ route, verb, auth }).end(() => {});
    });
  });
});
