'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');
const sinon = require('sinon');

const route = '/auth';

describe('/auth', function () {
  before(bootstrap(__dirname)); // provider, agent, this.AuthorizationRequest, wrap

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} response_mode=form_post`, function () {
      context('logged in', function () {
        before(function () { return this.login(); });
        after(function () { return this.logout(); });

        it('responds by rendering a self-submitting form with the code', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            response_mode: 'form_post',
            scope: 'openid'
          });

          return this.wrap({ route, verb, auth })
          .expect(200)
          .expect(/input type="hidden" name="code" value=/)
          .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
          .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });
      });

      context('error handling', function () {
        it('responds by rendering a self-submitting form with the error', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            prompt: 'none',
            response_mode: 'form_post',
            scope: 'openid'
          });

          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);

          return this.wrap({ route, verb, auth })
          .expect(200)
          .expect(() => {
            expect(spy.called).to.be.true;
          })
          .expect(new RegExp('input type="hidden" name="error" value="login_required"'))
          .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
          .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });

        context('[exception]', function () {
          before(function () {
            sinon.stub(this.provider.Client, 'find').returns(Promise.reject(new Error()));
          });

          after(function () {
            this.provider.Client.find.restore();
          });

          it('responds by rendering a self-submitting form with the exception', function () {
            const auth = new this.AuthorizationRequest({
              response_type: 'code',
              prompt: 'none',
              response_mode: 'form_post',
              scope: 'openid'
            });

            const spy = sinon.spy();
            this.provider.once('server_error', spy);

            return this.wrap({ route, verb, auth })
            .expect(200)
            .expect(() => {
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
});
