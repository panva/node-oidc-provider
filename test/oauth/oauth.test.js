import { describe, before, afterEach, it, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseUrl } from 'node:url';

import sinon from 'sinon';
import snakeCase from 'lodash/snakeCase.js';

import bootstrap, { skipConsent } from '../test_helper.js';

describe('requests without the openid scope', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => {
    fixture.provider.removeAllListeners();
  }, { timeout: 3000 });

  describe('openid scope gated parameters', () => {
    const fixture1 = Object.create(fixture);

    ['acr_values', 'claims', 'claims_locales', 'id_token_hint', 'max_age', 'nonce'].forEach((param) => {
      it(`${param} can only be used when openid is amongst the requested scopes`, { timeout: 3000 }, async () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type: 'code',
          [param]: 'foo',
        });

        await fixture1.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription(`openid scope must be requested when using the ${param} parameter`));
      });
    });

    Object.entries({
      defaultAcrValues: ['foo'],
      defaultMaxAge: 300,
      requireAuthTime: true,
    }).forEach(([clientProperty, value]) => {
      it(`must be provided when client is configured with ${snakeCase(clientProperty)}`, { timeout: 3000 }, async () => {
        const auth = new fixture1.AuthorizationRequest({
          client_id: 'client',
          response_type: 'code',
        });

        const client = await fixture1.provider.Client.find('client');

        client[clientProperty] = value;

        await fixture1.wrap({ route: '/auth', verb: 'get', auth })
          .expect(() => {
            delete client[clientProperty];
          })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription(`openid scope must be requested for clients with ${snakeCase(clientProperty)}`));
      });
    });
  });

  describe('response_types and flows that work when scope parameter is missing openid scope', () => {
    const fixture2 = Object.create(fixture);

    const scope = 'api:read';
    describe('when scope is e.g. missing openid (api:read)', () => {
      const fixture3 = Object.create(fixture2);

      before(() => fixture3.login({ scope: [scope, 'offline_access'].join(' ') }), { timeout: 3000 });
      after(() => fixture3.logout(), { timeout: 3000 });

      describe('response_type=code', () => {
        const fixture4 = Object.create(fixture3);

        const response_type = 'code';
        it('gets a code from the authorization endpoint', { timeout: 3000 }, async () => {
          const auth = new fixture4.AuthorizationRequest({
            response_type,
            scope,
          });

          const spy = sinon.spy();
          fixture4.provider.on('authorization_code.saved', spy);

          await fixture4.wrap({ route: '/auth', verb: 'get', auth })
            .expect(303)
            .expect(auth.validateClientLocation)
            .expect(auth.validatePresence(['code', 'state']));

          assert.equal(spy.calledOnce, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, scope); })(spy.args[0][0]);
        });

        describe('authorization code exchange', () => {
          const fixture5 = Object.create(fixture4);

          beforeEach(async () => {
            // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
            const auth = fixture5.auth = new fixture5.AuthorizationRequest({
              response_type,
              scope,
            });

            await fixture5.wrap({ route: '/auth', verb: 'get', auth })
              .expect(303)
              .expect(auth.validateClientLocation)
              .expect(auth.validatePresence(['code', 'state']))
              .expect((response) => {
                const { query: { code } } = parseUrl(response.headers.location, true);
                fixture5.code = code;
              });
          }, { timeout: 3000 });

          it('gets an access token', { timeout: 3000 }, async () => {
            const spy = sinon.spy();
            fixture5.provider.on('access_token.saved', spy);
            fixture5.provider.on('access_token.issued', spy);

            await fixture5.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'authorization_code',
                code_verifier: fixture5.auth.code_verifier,
                code: fixture5.code,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                assert.ok('access_token' in Object(body));
                assert.ok(!('id_token' in Object(body)));
              });

            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, scope); })(spy.args[0][0]);
          });

          it('gets an access token and a refresh token', { timeout: 3000 }, async () => {
            const adapter = fixture5.TestAdapter.for('AuthorizationCode');
            const jti = fixture5.getTokenJti(fixture5.code);

            const refreshScope = `${scope || ''} offline_access`.trim();

            adapter.syncUpdate(jti, {
              scope: refreshScope,
            });

            const spy = sinon.spy();
            fixture5.provider.on('access_token.saved', spy);
            fixture5.provider.on('access_token.issued', spy);
            fixture5.provider.on('refresh_token.saved', spy);

            await fixture5.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'authorization_code',
                code_verifier: fixture5.auth.code_verifier,
                code: fixture5.code,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                assert.ok('access_token' in Object(body));
                assert.ok('refresh_token' in Object(body));
                assert.ok(!('id_token' in Object(body)));
              });

            assert.equal(spy.calledTwice, true);
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, refreshScope); })(spy.args[0][0]);
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, refreshScope); })(spy.args[1][0]);
          });
        });

        describe('refresh token exchange', () => {
          const fixture6 = Object.create(fixture4);

          skipConsent(fixture6);
          const refreshScope = `${scope || ''} offline_access`.trim();

          before(() => fixture6.login({ scope: [scope, 'offline_access'].join(' ') }), { timeout: 3000 });

          beforeEach(async () => {
            const auth = new fixture6.AuthorizationRequest({
              response_type,
              scope: refreshScope,
              prompt: 'consent',
            });

            let code;
            await fixture6.wrap({ route: '/auth', verb: 'get', auth })
              .expect(303)
              .expect(auth.validateClientLocation)
              .expect(auth.validatePresence(['code', 'state']))
              .expect((response) => {
                ({ query: { code } } = parseUrl(response.headers.location, true));
              });

            await fixture6.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'authorization_code',
                code_verifier: auth.code_verifier,
                code,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                fixture6.rt = body.refresh_token;
              });
          }, { timeout: 3000 });

          it('gets an access token and a refresh token', { timeout: 3000 }, async () => {
            const spy = sinon.spy();
            fixture6.provider.on('access_token.saved', spy);
            fixture6.provider.on('access_token.issued', spy);
            fixture6.provider.on('refresh_token.saved', spy);

            await fixture6.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'refresh_token',
                refresh_token: fixture6.rt,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                assert.ok('access_token' in Object(body));
                assert.ok('refresh_token' in Object(body));
                assert.ok(!('id_token' in Object(body)));
              });

            assert.equal(spy.calledTwice, true);
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, refreshScope); })(spy.args[0][0]);
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, refreshScope); })(spy.args[1][0]);
          });
        });
      });

      describe('response_type=none', () => {
        const fixture7 = Object.create(fixture3);

        const response_type = 'none';

        it('gets nothing from the authorization endpoint', { timeout: 3000 }, async () => {
          const auth = new fixture7.AuthorizationRequest({
            response_type,
            scope,
          });

          const spy = sinon.spy();
          fixture7.provider.on('authorization.success', spy);

          await fixture7.wrap({ route: '/auth', verb: 'get', auth })
            .expect(303)
            .expect(auth.validateClientLocation)
            .expect(auth.validatePresence(['state']));

          assert.equal(spy.calledOnce, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.deepEqual(actual.scope, scope); })(spy.args[0][0].oidc.params);
        });
      });
    });

    describe('device flow', () => {
      const fixture8 = Object.create(fixture2);

      before(() => fixture8.login({ scope: [scope, 'offline_access'].join(' ') }), { timeout: 3000 });
      it('accepts the device authorization request', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture8.provider.on('device_code.saved', spy);

        await fixture8.agent.post('/device/auth')
          .send({
            client_id: 'client',
            scope,
          })
          .type('form')
          .expect(200);

        assert.equal(spy.calledOnce, true);
        if (scope) {
          ((actual) => { assert.ok("scope" in Object(actual.params)); assert.equal(actual.params.scope, scope); })(spy.args[0][0]);
        } else {
          assert.ok(!("scope" in Object(spy.args[0][0].params)));
        }
      });

      describe('urn:ietf:params:oauth:grant-type:device_code', () => {
        const fixture9 = Object.create(fixture8);

        beforeEach(async () => {
          fixture9.provider.on('device_code.saved', (token) => {
            fixture9.jti = token.jti;
          });

          await fixture9.agent.post('/device/auth')
            .send({
              client_id: 'client',
              scope,
            })
            .type('form')
            .expect(200)
            .expect(({ body }) => {
              fixture9.code = body.device_code;
            });

          fixture9.TestAdapter.for('DeviceCode').syncUpdate(fixture9.jti, {
            scope,
            accountId: fixture9.loggedInAccountId,
            grantId: fixture9.getGrantId('client'),
            clientId: 'client',
          });
        }, { timeout: 3000 });

        it('gets an access token', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture9.provider.on('access_token.saved', spy);
          fixture9.provider.on('access_token.issued', spy);

          await fixture9.agent.post('/token')
            .send({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: fixture9.code,
            })
            .type('form')
            .expect(200)
            .expect(({ body }) => {
              assert.ok('access_token' in Object(body));
              assert.ok(!('id_token' in Object(body)));
            });

          assert.equal(spy.calledOnce, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, scope); })(spy.args[0][0]);
        });

        it('gets an access and a refresh_token', { timeout: 3000 }, async () => {
          const refreshScope = `${scope || ''} offline_access`.trim();
          const spy = sinon.spy();
          fixture9.provider.on('access_token.saved', spy);
          fixture9.provider.on('access_token.issued', spy);
          fixture9.provider.on('refresh_token.saved', spy);

          fixture9.TestAdapter.for('DeviceCode').syncUpdate(fixture9.jti, {
            scope: refreshScope,
          });

          await fixture9.agent.post('/token')
            .send({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: fixture9.code,
            })
            .type('form')
            .expect(200)
            .expect(({ body }) => {
              assert.ok('access_token' in Object(body));
              assert.ok('refresh_token' in Object(body));
              assert.ok(!('id_token' in Object(body)));
            });

          assert.equal(spy.calledTwice, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, refreshScope); })(spy.args[0][0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, refreshScope); })(spy.args[1][0]);
        });
      });
    });
  });

  describe('response_types that require openid scope', () => {
    const fixture10 = Object.create(fixture);

    ['code id_token token', 'code id_token', 'id_token token', 'id_token'].forEach((response_type) => {
      it(`scope must be present when requesting ${response_type}`, { timeout: 3000 }, async () => {
        const auth = new fixture10.AuthorizationRequest({
          response_type,
        });

        delete auth.scope;
        delete auth.state;

        await fixture10.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('openid scope must be requested for this response_type'));
      });

      it(`openid scope value must be present when requesting ${response_type}`, { timeout: 3000 }, async () => {
        const auth = new fixture10.AuthorizationRequest({
          response_type,
          scope: 'api:read',
        });

        delete auth.state;

        await fixture10.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('openid scope must be requested for this response_type'));
      });
    });
  });
});
