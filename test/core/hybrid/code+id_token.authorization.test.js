import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap, { skipConsent } from '../../test_helper.js';

const route = '/auth';
const response_type = 'code id_token';
const scope = 'openid';

describe('HYBRID code+id_token', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, () => {
      const fixture1 = Object.create(fixture);

      before(() => fixture1.login(), { timeout: 3000 });

      it('responds with a id_token and code in fragment', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('handles mixed up response_type order', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type: 'id_token code',
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture1.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Grant', 'Account', 'AuthorizationCode', 'Session']));
        }, done);

        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        fixture1.wrap({ route, verb, auth }).end(() => {});
      });

      describe('ignoring the offline_access scope', () => {
        const fixture2 = Object.create(fixture1);

        skipConsent(fixture2);

        it('ignores the scope offline_access unless prompt consent is present', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture2.provider.once('authorization_code.saved', spy);

          const auth = new fixture2.AuthorizationRequest({
            response_type,
            scope: 'openid offline_access',
          });

          return fixture2.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validateClientLocation)
            .expect(() => {
              ((actual) => { assert.ok('scope' in Object(actual)); assert.ok(!(actual.scope.includes('offline_access'))); })(spy.firstCall.args[0]);
            });
        });

        it('ignores the scope offline_access unless the client can do refresh_token exchange', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture2.provider.once('authorization_code.saved', spy);

          const auth = new fixture2.AuthorizationRequest({
            client_id: 'client-no-refresh',
            response_type,
            scope: 'openid offline_access',
          });

          return fixture2.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validateClientLocation)
            .expect(() => {
              ((actual) => { assert.ok('scope' in Object(actual)); assert.ok(!(actual.scope.includes('offline_access'))); })(spy.firstCall.args[0]);
            });
        });
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

      it('missing mandatory parameter nonce', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture3.provider.once('authorization.error', spy);
        const auth = new fixture3.AuthorizationRequest({
          response_type,
          scope,
        });
        delete auth.nonce;

        return fixture3.agent.get(route)
          .query(auth)
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("missing required parameter 'nonce'"));
      });
    });
  });
});
