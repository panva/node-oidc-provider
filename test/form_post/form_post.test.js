const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

const route = '/auth';

describe('/auth', () => {
  before(bootstrap(__dirname));

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} response_mode=form_post`, () => {
      context('logged in', () => {
        before(function () { return this.login(); });
        after(function () { return this.logout(); });

        it('responds by rendering a self-submitting form with the response', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code id_token token',
            response_mode: 'form_post',
            scope: 'openid',
          });

          return this.wrap({ route, verb, auth })
            .expect(200)
            .expect(/input type="hidden" name="code" value=/)
            .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
            .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });
      });

      context('error handling', () => {
        it('responds by rendering a self-submitting form with the error', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            prompt: 'none',
            response_mode: 'form_post',
            scope: 'openid',
          });

          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);

          return this.wrap({ route, verb, auth })
            .expect(400)
            .expect(() => {
              expect(spy.called).to.be.true;
            })
            .expect(new RegExp('input type="hidden" name="error" value="login_required"'))
            .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
            .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });

        context('[exception]', () => {
          before(async function () {
            sinon.stub(this.provider.Session.prototype, 'accountId').throws();
          });

          after(async function () {
            this.provider.Session.prototype.accountId.restore();
          });

          it('responds by rendering a self-submitting form with the exception', function () {
            const auth = new this.AuthorizationRequest({
              response_type: 'code',
              prompt: 'none',
              response_mode: 'form_post',
              scope: 'openid',
            });

            const spy = sinon.spy();
            this.provider.once('server_error', spy);

            return this.wrap({ route, verb, auth })
              .expect(500)
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
