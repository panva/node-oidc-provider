import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import * as querystring from 'node:querystring';
import * as url from 'node:url';

import sinon from 'sinon';

import bootstrap from '../../test_helper.js';

const route = '/auth';
const response_type = 'id_token';
const scope = 'openid';

describe('IMPLICIT id_token', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  ['get', 'post'].forEach((verb) => {
    describe(`IMPLICIT id_token ${verb} ${route} with session`, () => {
      const fixture1 = Object.create(fixture);

      before(() => fixture1.login(), { timeout: 3000 });

      it('responds with a id_token in fragment', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture1.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Grant', 'Account', 'Session']));
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

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });
    });

    describe(`IMPLICIT id_token ${verb} ${route} errors`, () => {
      const fixture2 = Object.create(fixture);

      before(() => fixture2.login(), { timeout: 3000 });

      it('disallowed response mode', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once('authorization.error', spy);
        const auth = new fixture2.AuthorizationRequest({
          response_type,
          scope,
          response_mode: 'query',
        });

        return fixture2.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          // .expect(auth.validateFragment) // response mode will be honoured for error response
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('requested response_mode is not allowed for the requested response_type'));
      });

      it('HMAC ID Token Hint with expired secret errors', { timeout: 3000 }, async () => {
        const client = await fixture2.provider.Client.find('client-expired-secret');
        client.clientSecretExpiresAt = 0;

        let auth = new fixture2.AuthorizationRequest({
          client_id: 'client-expired-secret',
          response_type,
          scope,
        });

        let idTokenHint;
        await fixture2.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect((response) => {
            const { query } = url.parse(response.headers.location.replace('#', '?'), true);
            idTokenHint = query.id_token;
          });

        client.clientSecretExpiresAt = 1;

        const spy = sinon.spy();
        fixture2.provider.once('authorization.error', spy);
        auth = new fixture2.AuthorizationRequest({
          client_id: 'client-expired-secret',
          response_type,
          id_token_hint: idTokenHint,
          scope,
        });

        return fixture2.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validateFragment) // response mode will be honoured for error response
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired - cannot validate ID Token Hint'));
      });

      it('HMAC ID Token with expired secret errors', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once('authorization.error', spy);
        const auth = new fixture2.AuthorizationRequest({
          client_id: 'client-expired-secret',
          response_type,
          scope,
        });

        return fixture2.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validateFragment) // response mode will be honoured for error response
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired - cannot issue an ID Token (HS256)'));
      });

      it('response mode provided twice', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once('authorization.error', spy);
        const auth = new fixture2.AuthorizationRequest({
          response_type,
          scope,
          response_mode: 'fragment',
        });

        const wrapped = ((data) => {
          switch (verb) {
            case 'get':
              return fixture2.agent
                .get(route)
                .query(`${data}&response_mode=fragment`);
            case 'post':
              return fixture2.agent
                .post(route)
                .send(`${data}&response_mode=fragment`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validateFragment) // mode will still be figured out from the response_type
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'response_mode' parameter must not be provided twice"));
      });

      it('missing mandatory parameter nonce', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once('authorization.error', spy);
        const auth = new fixture2.AuthorizationRequest({
          response_type,
          scope,
        });
        delete auth.nonce;

        return fixture2.agent.get(route)
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
