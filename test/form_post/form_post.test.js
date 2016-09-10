'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');
const sinon = require('sinon');

const route = '/auth';

['get', 'post'].forEach((verb) => {
  describe(`${verb} ${route} response_mode=form_post`, function () {
    const { provider, agent, AuthorizationRequest, wrap } = bootstrap(__dirname);
    const Client = provider.get('Client');

    provider.setupClient();
    provider.setupCerts();

    context('logged in', function () {
      before(agent.login);
      after(agent.logout);

      it('responds by rendering a self-submitting form with the code', function () {
        const auth = new AuthorizationRequest({
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

    context('error handling', function () {
      it('responds by rendering a self-submitting form with the error', function () {
        const auth = new AuthorizationRequest({
          response_type: 'code',
          prompt: 'none',
          response_mode: 'form_post',
          scope: 'openid'
        });

        const spy = sinon.spy();
        provider.once('authorization.error', spy);

        return wrap({ agent, route, verb, auth })
        .expect(200)
        .expect(function () {
          expect(spy.called).to.be.true;
        })
        .expect(new RegExp('input type="hidden" name="error" value="login_required"'))
        .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
        .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
      });

      context('[exception]', function () {
        before(function () {
          sinon.stub(Client, 'find').returns(Promise.reject(new Error()));
        });

        after(function () {
          Client.find.restore();
        });

        it('responds by rendering a self-submitting form with the exception', function () {
          const auth = new AuthorizationRequest({
            response_type: 'code',
            prompt: 'none',
            response_mode: 'form_post',
            scope: 'openid'
          });

          const spy = sinon.spy();
          provider.once('server_error', spy);

          return wrap({ agent, route, verb, auth })
          .expect(200)
          .expect(function () {
            expect(spy.called).to.be.true;
          })
          .expect(new RegExp('input type="hidden" name="error" value="server_error"'))
          .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
          .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });
      });
    });
  });
});
