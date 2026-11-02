import { describe, before, after, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';
import safe from '../../lib/helpers/html_safe.js';

const route = '/auth';

describe('/auth', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} response_mode=form_post`, () => {
      const fixture1 = Object.create(fixture);

      describe('logged in', () => {
        const fixture2 = Object.create(fixture1);

        before(() => fixture2.login(), { timeout: 3000 });
        after(() => fixture2.logout(), { timeout: 3000 });

        it('responds by rendering a self-submitting form with the response', { timeout: 3000 }, () => {
          const auth = new fixture2.AuthorizationRequest({
            response_type: 'code id_token token',
            response_mode: 'form_post',
            scope: 'openid',
          });

          return fixture2.wrap({ route, verb, auth })
            .expect(200)
            .expect(/input type="hidden" name="code" value=/)
            .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
            .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });

        it('sanitizes the action attribute', { timeout: 3000 }, () => {
          const auth = new fixture2.AuthorizationRequest({
            response_type: 'code id_token token',
            response_mode: 'form_post',
            scope: 'openid',
            redirect_uri: 'https://client.example.com/cb"><script>alert(0)</script><x="',
          });

          return fixture2.wrap({ route, verb, auth })
            .expect(200)
            .expect(({ text: body }) => {
              assert.ok(body.includes(safe(auth.redirect_uri)));
            });
        });
      });

      describe('error handling', () => {
        const fixture3 = Object.create(fixture1);

        it('responds by rendering a self-submitting form with the error', { timeout: 3000 }, () => {
          const auth = new fixture3.AuthorizationRequest({
            response_type: 'code',
            prompt: 'none',
            response_mode: 'form_post',
            scope: 'openid',
          });

          const spy = sinon.spy();
          fixture3.provider.once('authorization.error', spy);

          return fixture3.wrap({ route, verb, auth })
            .expect(400)
            .expect(() => {
              assert.equal(spy.called, true);
            })
            .expect(/input type="hidden" name="error" value="login_required"/)
            .expect(new RegExp(`input type="hidden" name="state" value="${auth.state}"`))
            .expect(new RegExp(`form method="post" action="${auth.redirect_uri}"`));
        });
      });
    });
  });
});
