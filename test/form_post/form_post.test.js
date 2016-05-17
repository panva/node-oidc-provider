'use strict';

const {
  provider, agent, AuthenticationRequest, wrap
} = require('../test_helper')(__dirname);

const route = '/auth';

provider.setupClient();
provider.setupCerts();

['get', 'post'].forEach((verb) => {
  describe(`${verb} ${route} response_mode=form_post`, function () {
    context('logged in', function () {
      before(agent.login);
      after(agent.logout);

      it('responds by rendering a self-submitting form with the code', function () {
        const auth = new AuthenticationRequest({
          response_type: 'code',
          response_mode: 'form_post',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
        .expect(200)
        .expect(/input type="hidden" name="code" value=/)
        .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
        .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
      });
    });

    context('errors', function () {
      it('responds by rendering a self-submitting form with the error', function () {
        const auth = new AuthenticationRequest({
          response_type: 'code',
          prompt: 'none',
          response_mode: 'form_post',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
        .expect(200)
        .expect(new RegExp('input type="hidden" name="error" value="login_required"'))
        .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
        .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
      });
    });
  });
});
