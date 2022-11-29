import { expect } from 'chai';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';
import safe from '../../lib/helpers/html_safe.js';

const route = '/auth';

describe('/auth', () => {
  before(bootstrap(import.meta.url));

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

        it('sanitizes the action attribute', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code id_token token',
            response_mode: 'form_post',
            scope: 'openid',
            redirect_uri: 'https://client.example.com/cb"><script>alert(0)</script><x="',
          });

          return this.wrap({ route, verb, auth })
            .expect(200)
            .expect(({ text: body }) => {
              expect(body).to.contain(safe(auth.redirect_uri));
            });
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
            .expect(/input type="hidden" name="error" value="login_required"/)
            .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
            .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });
      });
    });
  });
});
