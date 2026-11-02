import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../../test_helper.js';

const route = '/auth';
const response_type = 'code token';
const scope = 'openid';

describe('HYBRID code+token', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  afterEach(() => {
    fixture.provider.removeAllListeners();
  }, { timeout: 3000 });

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, () => {
      const fixture1 = Object.create(fixture);

      before(() => fixture1.login(), { timeout: 3000 });

      it('responds with a access_token and code in fragment', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('handles mixed up response_type order', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type: 'token code',
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture1.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Grant', 'Account', 'AuthorizationCode', 'AccessToken', 'Session']));
        }, done);

        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        fixture1.wrap({ route, verb, auth }).end(() => {});
      });

      it('ignores the scope offline_access unless prompt consent is present', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture1.provider.once('authorization_code.saved', spy);
        fixture1.provider.once('access_token.saved', spy);
        fixture1.provider.once('access_token.issued', spy);

        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope: 'openid offline_access',
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect(() => {
            ((actual) => { assert.ok('scope' in Object(actual)); assert.ok(!(actual.scope.includes('offline_access'))); })(spy.firstCall.args[0]);
            ((actual) => { assert.ok('scope' in Object(actual)); assert.ok(!(actual.scope.includes('offline_access'))); })(spy.secondCall.args[0]);
          });
      });
    });

    describe(`${verb} ${route} with the scope not being fulfilled`, () => {
      const fixture2 = Object.create(fixture);

      before(() => fixture2.login({
          scope: 'openid profile email',
          rejectedScopes: ['email'],
        }), { timeout: 3000 });

      it('responds with an extra parameter scope', { timeout: 3000 }, async () => {
        const auth = new fixture2.AuthorizationRequest({
          response_type,
          scope: 'openid profile email',
        });

        await fixture2.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateResponseParameter('scope', 'openid profile'));
      });
    });

    describe(`${verb} ${route} errors`, () => {
      const fixture3 = Object.create(fixture);

      it('disallowed response mode', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture3.provider.once('authorization.error', spy);
        const auth = new fixture3.AuthorizationRequest({
          response_type,
          scope,
          response_mode: 'query',
        });

        return fixture3.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('requested response_mode is not allowed for the requested response_type'));
      });
    });
  });
});
