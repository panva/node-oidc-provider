import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../../test_helper.js';

const route = '/auth';
const response_type = 'id_token token';
const scope = 'openid';

describe('IMPLICIT id_token+token', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  afterEach(() => {
    fixture.provider.removeAllListeners();
  }, { timeout: 3000 });

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, () => {
      const fixture1 = Object.create(fixture);

      before(() => fixture1.login(), { timeout: 3000 });

      it('responds with a id_token and access_token in fragment', { timeout: 3000 }, async () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        await fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'implicit'); })(await fixture1.provider.AccessToken.find(auth.res.access_token));
      });

      it('handles mixed up response_type order', { timeout: 3000 }, async () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type: 'token id_token',
          scope,
        });

        await fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'implicit'); })(await fixture1.provider.AccessToken.find(auth.res.access_token));
      });

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture1.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Grant', 'Account', 'AccessToken', 'Session']));
        }, done);

        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        fixture1.wrap({ route, verb, auth }).end(() => {});
      });

      it('ignores offline_access scope for non code-including response_types', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope: 'openid offline_access',
        });

        const spy = sinon.spy();
        fixture1.provider.once('access_token.saved', spy);
        fixture1.provider.once('access_token.issued', spy);

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .then(() => {
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid'); })(spy.getCall(0).firstArg);
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
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
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
