const bootstrap = require('../test_helper');
const { expect } = require('chai');

const route = '/auth';

describe('session management', () => {
  before(bootstrap(__dirname)); // provider, agent, this.AuthorizationRequest, wrap

  ['get', 'post'].forEach((verb) => {
    describe(`[session_management] ${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('provides session_state in the response', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validatePresence(['session_state'], false))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('sets a _state.clientId cookies', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(() => {
            const state = this.agent.jar.getCookie('_state.client', { path: '/' });
            expect(state).to.be.ok;
          });
      });
    });

    describe('[session_management] check_session_iframe', () => {
      before(function () {
        this.provider.use(async (ctx, next) => {
          ctx.response.set('X-Frame-Options', 'SAMEORIGIN');
          ctx.response.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'self' example.com *.example.net; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';");
          await next();
        });
      });

      it('responds with frameable html', function () {
        return this.agent.get('/session/check')
          .expect(200)
          .expect('content-type', /text\/html/)
          .expect((response) => {
            expect(response.headers['x-frame-options']).not.to.be.ok;
            expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
          });
      });
    });
  });
});
