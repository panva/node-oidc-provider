import { describe, before, it, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import * as querystring from 'node:querystring';

import sinon from 'sinon';

import bootstrap, { skipConsent } from '../../test_helper.js';
import epochTime from '../../../lib/helpers/epoch_time.js';
import {
  InvalidRequest,
  InvalidClient,
  InvalidRedirectUri,
} from '../../../lib/helpers/errors.js';

const route = '/auth';
const response_type = 'code';
const scope = 'openid';

describe('BASIC code', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, () => {
      const fixture1 = Object.create(fixture);

      before(() => fixture1.login(), { timeout: 3000 });

      it('responds with a code in search', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('responds with a code in fragment', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          response_mode: 'fragment',
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture1.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['AuthorizationCode', 'Grant', 'Client', 'Account', 'Session']));
          ((actual) => { assert.ok("extra" in Object(actual)); assert.equal(actual.extra, 'provided'); assert.ok("extra2" in Object(actual)); assert.equal(actual.extra2, 'defaulted'); })(ctx.oidc.params);
        }, done);

        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope,
          extra: 'provided',
        });

        fixture1.wrap({ route, verb, auth }).end(() => {});
      });

      it('allows native apps to do none auth check when already authorized', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type: 'none',
          prompt: 'none',
          client_id: 'client-native',
          redirect_uri: 'com.example.app:/cb',
          scope,
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('ignores unsupported scopes', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture1.provider.once('authorization_code.saved', spy);
        const auth = new fixture1.AuthorizationRequest({
          response_type,
          scope: 'openid and unsupported',
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(() => {
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid'); })(spy.firstCall.args[0]);
          });
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
            prompt: 'consent',
            scope: 'openid offline_access',
          });

          return fixture2.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateClientLocation)
            .expect(() => {
              ((actual) => { assert.ok('scope' in Object(actual)); assert.ok(!(actual.scope.includes('offline_access'))); })(spy.firstCall.args[0]);
            });
        });
      });
    });

    describe(`${verb} ${route} interactions`, () => {
      const fixture3 = Object.create(fixture);

      before(() => fixture3.logout(), { timeout: 3000 });
      before(() => {
        fixture3.policy = i(fixture3.provider).configuration.interactions.policy;
        i(fixture3.provider).configuration.interactions.policy = [];
      }, { timeout: 3000 });

      after(() => {
        i(fixture3.provider).configuration.interactions.policy = fixture3.policy;
      }, { timeout: 3000 });

      it('no account id was resolved and no interactions requested', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture3.provider.on('authorization.error', spy);

        const auth = new fixture3.AuthorizationRequest({
          response_type,
          scope,
        });

        await fixture3.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(auth.validatePresence(['error', 'state']))
          .expect(auth.validateError('access_denied'));

        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'authorization request resolved without requesting interactions but no account id was resolved'); })(spy.args[0][1]);
      });

      it('no scope was resolved and no interactions requested', { timeout: 3000 }, async () => {
        await fixture3.login();
        const spy = sinon.spy();
        fixture3.provider.on('authorization.error', spy);

        const auth = new fixture3.AuthorizationRequest({
          response_type,
          // scope,
        });

        await fixture3.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(auth.validatePresence(['error', 'state']))
          .expect(auth.validateError('access_denied'));

        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'authorization request resolved without requesting interactions but no scope was granted'); })(spy.args[0][1]);
      });
    });

    describe(`${verb} ${route} interactions`, () => {
      const fixture4 = Object.create(fixture);

      beforeEach(() => fixture4.login(), { timeout: 3000 });
      after(() => fixture4.logout(), { timeout: 3000 });

      it('no account id was found in the session info', { timeout: 3000 }, () => {
        const session = fixture4.getSession();
        delete session.loginTs;
        delete session.accountId;

        const auth = new fixture4.AuthorizationRequest({
          response_type,
          scope,
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'no_session'));
      });

      it('additional scopes are requested', { timeout: 3000 }, () => {
        const auth = new fixture4.AuthorizationRequest({
          response_type,
          scope: 'openid email',
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('consent', 'op_scopes_missing'));
      });

      it('are required for native clients by default', { timeout: 3000 }, () => {
        const auth = new fixture4.AuthorizationRequest({
          response_type,
          client_id: 'client-native',
          redirect_uri: 'com.example.app:/cb',
          scope,
          code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
          code_challenge_method: 'S256',
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('consent', 'native_client_prompt'));
      });

      it('login was requested by the client by prompt parameter', { timeout: 3000 }, () => {
        const auth = new fixture4.AuthorizationRequest({
          response_type,
          prompt: 'login',
          scope,
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'login_prompt'));
      });

      it('login was requested by the client by max_age=0', { timeout: 3000 }, () => {
        const auth = new fixture4.AuthorizationRequest({
          response_type,
          max_age: 0,
          scope,
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'login_prompt'));
      });

      it('interaction check no session & max_age combo', { timeout: 3000 }, () => {
        fixture4.logout();

        const auth = new fixture4.AuthorizationRequest({
          response_type,
          max_age: '1800', // 30 minutes old session max
          scope,
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age', 'no_session'));
      });

      it('session is too old for this authorization request (1/2)', { timeout: 3000 }, () => {
        const session = fixture4.getSession();
        session.loginTs = epochTime() - 3600; // an hour ago

        const auth = new fixture4.AuthorizationRequest({
          response_type,
          max_age: '1800', // 30 minutes old session max
          scope,
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age'));
      });

      it('session is too old for this authorization request (2/2)', { timeout: 3000 }, () => {
        const session = fixture4.getSession();
        delete session.loginTs;

        const auth = new fixture4.AuthorizationRequest({
          response_type,
          max_age: '1800', // 30 minutes old session max
          scope,
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age'));
      });

      it('custom interactions can be requested', { timeout: 3000 }, () => {
        const auth = new fixture4.AuthorizationRequest({
          response_type,
          scope,
          triggerCustomFail: 'foo',
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'reason_foo'));
      });

      it('session is too old for this client', { timeout: 3000 }, async () => {
        const client = await fixture4.provider.Client.find('client');
        client.defaultMaxAge = 1800;

        const session = fixture4.getSession();
        session.loginTs = epochTime() - 3600; // an hour ago

        const auth = new fixture4.AuthorizationRequest({
          response_type,
          scope,
        });

        return fixture4.wrap({ route, verb, auth })
          .expect(() => {
            delete client.defaultMaxAge;
          })
          .expect(303)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age'));
      });
    });

    describe(`${verb} ${route} errors`, () => {
      const fixture5 = Object.create(fixture);

      it('dupe parameters are rejected and ignored in further processing', { timeout: 3000 }, () => {
        // fake a query like this state=foo&state=foo
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          state: 'foo',
        });

        const wrapped = ((data) => {
          switch (verb) {
            case 'get':
              return fixture5.agent
                .get(route)
                .query(`${data}&state=foo&scope=openid&response_type=${response_type}`);
            case 'post':
              return fixture5.agent
                .post(route)
                .send(`${data}&state=foo&scope=openid&response_type=${response_type}`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          // .expect(auth.validateState) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'response_type', 'scope', and 'state' parameters must not be provided twice"));
      });

      it('invalid response mode (not validated yet)', { timeout: 3000 }, () => {
        // fake a query like this state=foo&state=foo to trigger
        // a validation error prior to validating response mode
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          state: 'foo',
          response_mode: 'foo',
        });

        const wrapped = ((data) => {
          switch (verb) {
            case 'get':
              return fixture5.agent
                .get(route)
                .query(`${data}&state=bar`);
            case 'post':
              return fixture5.agent
                .post(route)
                .send(`${data}&state=bar`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          // .expect(auth.validateState) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'state' parameter must not be provided twice"));
      });

      it('response mode provided twice', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          response_mode: 'query',
        });

        const wrapped = ((data) => {
          switch (verb) {
            case 'get':
              return fixture5.agent
                .get(route)
                .query(`${data}&response_mode=query`);
            case 'post':
              return fixture5.agent
                .post(route)
                .send(`${data}&response_mode=query`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'response_mode' parameter must not be provided twice"));
      });

      it('unregistered scope requested', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          client_id: 'client-limited-scope',
          response_type: 'code',
          prompt: 'consent',
          scope: 'openid foobar offline_access', // foobar is ignored, offline_access is not allowed
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_scope'))
          .expect(auth.validateScope('offline_access'))
          .expect(auth.validateErrorDescription('requested scope is not allowed'));
      });

      it('rejects scope values outside the scope-token grammar', { timeout: 3000 }, () => {
        const auth = new fixture5.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid profile\ninjected',
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_scope'))
          .expect(auth.validateErrorDescription('scope contains invalid characters'));
      });

      it('disallowed response mode', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type: 'code token',
          scope,
          response_mode: 'query',
        });

        return fixture5.wrap({ route, verb, auth })
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

      ['request', 'request_uri', 'registration'].forEach((param) => {
        it(`not supported parameter ${param}`, { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture5.provider.once('authorization.error', spy);
          const auth = new fixture5.AuthorizationRequest({
            response_type,
            scope,
            [param]: 'some',
          });

          return fixture5.agent.get(route)
            .query(auth)
            .expect(303)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect(auth.validatePresence(['error', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError(`${param}_not_supported`));
        });
      });

      describe('when client has a single redirect_uri', () => {
        const fixture6 = Object.create(fixture5);

        after(async () => {
          i(fixture6.provider).configuration.allowOmittingSingleRegisteredRedirectUri = false;
          await fixture6.logout();
        }, { timeout: 3000 });

        it('missing mandatory parameter redirect_uri', { timeout: 3000 }, () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture6.provider).configuration, 'renderError');
          fixture6.provider.once('authorization.error', emitSpy);
          const auth = new fixture6.AuthorizationRequest({
            response_type,
            scope,
          });
          delete auth.redirect_uri;

          return fixture6.wrap({ route, verb, auth })
            .expect(() => {
              renderSpy.restore();
            })
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'missing required parameter \'redirect_uri\''); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
            });
        });

        it('unless allowOmittingSingleRegisteredRedirectUri is true', { timeout: 3000 }, async () => {
          i(fixture6.provider).configuration.allowOmittingSingleRegisteredRedirectUri = true;
          await fixture6.login();
          const auth = new fixture6.AuthorizationRequest({
            response_type,
            scope,
            client_id: 'client',
          });

          delete auth.redirect_uri;

          return fixture6.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validatePresence(['code', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });
      });

      describe('when client has more then one redirect_uri', () => {
        const fixture7 = Object.create(fixture5);

        before(async () => {
          const client = await fixture7.provider.Client.find('client');
          client.redirectUris.push('https://someOtherUri.com');
        }, { timeout: 3000 });

        after(async () => {
          const client = await fixture7.provider.Client.find('client');
          client.redirectUris.pop();
        }, { timeout: 3000 });

        it('missing mandatory parameter redirect_uri', { timeout: 3000 }, () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture7.provider).configuration, 'renderError');
          fixture7.provider.once('authorization.error', emitSpy);
          const auth = new fixture7.AuthorizationRequest({
            response_type,
            scope,
          });
          delete auth.redirect_uri;

          return fixture7.agent.get(route)
            .query(auth)
            .expect(() => {
              renderSpy.restore();
            })
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'missing required parameter \'redirect_uri\''); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
            });
        });
      });

      it('missing mandatory parameter response_type', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          scope,
        });
        delete auth.response_type;

        return fixture5.agent.get(route)
          .query(auth)
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('missing required parameter \'response_type\''));
      });

      it('unsupported prompt', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          prompt: 'unsupported',
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('unsupported prompt value requested'));
      });

      it('supported but not requestable prompt', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          prompt: 'unrequestable',
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('unsupported prompt value requested'));
      });

      it('bad prompt combination', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          prompt: 'none login',
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('prompt none must only be used alone'));
      });

      // section-4.1.2.1 RFC6749
      it('missing mandatory parameter client_id', { timeout: 3000 }, () => {
        const renderSpy = sinon.spy(i(fixture5.provider).configuration, 'renderError');
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
        });
        delete auth.client_id;

        return fixture5.agent.get(route)
          .query(auth)
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            assert.equal(renderSpy.calledOnce, true);
            const renderArgs = renderSpy.args[0];
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'missing required parameter \'client_id\''); })(renderArgs[1]);
            ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
          });
      });

      // section-4.1.2.1 RFC6749
      it('unrecognized client_id provided', { timeout: 3000 }, () => {
        const renderSpy = sinon.spy(i(fixture5.provider).configuration, 'renderError');
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          client_id: 'foobar',
        });

        return fixture5.agent.get(route)
          .query(auth)
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            assert.equal(renderSpy.calledOnce, true);
            const renderArgs = renderSpy.args[0];
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client'); })(renderArgs[1]);
            ((actual) => { assert.ok(actual instanceof InvalidClient); })(renderArgs[2]);
          });
      });

      describe('section-4.1.2.1 RFC6749', () => {
        const fixture8 = Object.create(fixture5);

        it('validates redirect_uri ad acta [regular error]', { timeout: 3000 }, () => {
          const renderSpy = sinon.spy(i(fixture8.provider).configuration, 'renderError');
          const spy = sinon.spy();
          fixture8.provider.on('authorization.error', spy);
          const auth = new fixture8.AuthorizationRequest({
            response_type,
            // scope, => 'openid' required when id_token_hint is provided
            id_token_hint: 'foo',
            redirect_uri: 'https://attacker.example.com/foobar',
          });

          return fixture8.agent.get(route)
            .query(auth)
            .expect(() => {
              fixture8.provider.removeAllListeners('authorization.error');
              renderSpy.restore();
            })
            .expect(() => {
              assert.equal(spy.calledTwice, true);
            })
            .expect(() => {
              assert.equal(spy.firstCall.calledWithMatch({}, { message: 'invalid_request' }), true);
              assert.equal(spy.secondCall.calledWithMatch({}, { message: 'invalid_redirect_uri' }), true);
            })
            .expect(() => {
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_redirect_uri'); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRedirectUri); })(renderArgs[2]);
            });
        });

        it('validates redirect_uri ad acta [server error]', { timeout: 3000 }, () => {
          const renderSpy = sinon.spy(i(fixture8.provider).configuration, 'renderError');
          const authErrorSpy = sinon.spy();
          const serverErrorSpy = sinon.spy();
          fixture8.provider.on('authorization.error', authErrorSpy);
          fixture8.provider.on('server_error', serverErrorSpy);
          sinon.stub(i(fixture8.provider).responseModes, 'has').callsFake(() => { throw new Error('foobar'); });
          const auth = new fixture8.AuthorizationRequest({
            response_type,
            scope,
            response_mode: 'fragment',
            redirect_uri: 'https://attacker.example.com/foobar',
          });

          return fixture8.agent.get(route)
            .query(auth)
            .expect(() => {
              i(fixture8.provider).responseModes.has.restore();
              fixture8.provider.removeAllListeners('authorization.error');
              fixture8.provider.removeAllListeners('server_error');
              renderSpy.restore();
            })
            .expect(() => {
              assert.equal(serverErrorSpy.calledOnce, true);
              assert.equal(authErrorSpy.calledOnce, true);
            })
            .expect(() => {
              assert.equal(serverErrorSpy.calledWithMatch({}, { message: 'foobar' }), true);
              assert.equal(authErrorSpy.calledWithMatch({}, { message: 'invalid_redirect_uri' }), true);
            })
            .expect(() => {
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_redirect_uri'); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRedirectUri); })(renderArgs[2]);
            });
        });
      });

      it('unsupported response_type', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type: 'unsupported',
          scope,
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('unsupported_response_type'))
          .expect(auth.validateErrorDescription('unsupported response_type requested'));
      });

      it('invalid max_age (negative)', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope: 'openid',
          max_age: -1,
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('invalid max_age parameter value'));
      });

      it('invalid max_age (MAX_SAFE_INTEGER)', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope: 'openid',
          max_age: Number.MAX_SAFE_INTEGER + 1,
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('invalid max_age parameter value'));
      });

      if (verb === 'post') {
        it('only supports application/x-www-form-urlencoded', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture5.provider.once('authorization.error', spy);
          const auth = new fixture5.AuthorizationRequest({
            response_type,
            scope,
          });

          return fixture5.wrap({ route, verb, auth })
            .type('json')
            .expect(400)
            .expect(/only application\/x-www-form-urlencoded content-type bodies are supported on POST \/auth/)
            .expect(/invalid_request/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            });
        });
      }

      it('restricted response_type', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type: 'id_token',
          scope,
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('requested response_type is not allowed for this client'));
      });

      it('unsupported response type validation runs before oidc required params', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);
        const auth = new fixture5.AuthorizationRequest({
          response_type: 'id_token token',
          nonce: undefined,
          scope,
        });

        return fixture5.wrap({ route, verb, auth })
          .expect(303)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('unsupported_response_type'))
          .expect(auth.validateErrorDescription('unsupported response_type requested'));
      });

      it('redirect_uri mismatch', { timeout: 3000 }, () => {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(fixture5.provider).configuration, 'renderError');
        fixture5.provider.once('authorization.error', emitSpy);
        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope,
          redirect_uri: 'https://client.example.com/cb/not/registered',
        });

        return fixture5.agent.get(route)
          .query(auth)
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            assert.equal(emitSpy.calledOnce, true);
            assert.equal(renderSpy.calledOnce, true);
            const renderArgs = renderSpy.args[0];
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_redirect_uri'); })(renderArgs[1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'redirect_uri did not match any of the client\'s registered redirect_uris'); })(renderArgs[1]);
            ((actual) => { assert.ok(actual instanceof InvalidRedirectUri); })(renderArgs[2]);
          });
      });

      for (const redirect_uri of [
        'https://client.example.com:443/cb',
        'https://CLIENT.EXAMPLE.COM/cb',
      ]) {
        it(`redirect_uri comparison uses exact string matching (${redirect_uri})`, { timeout: 3000 }, () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture5.provider).configuration, 'renderError');
          fixture5.provider.once('authorization.error', emitSpy);
          const auth = new fixture5.AuthorizationRequest({
            response_type,
            scope,
            redirect_uri,
          });

          return fixture5.wrap({ route, verb, auth })
            .expect(() => {
              renderSpy.restore();
            })
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_redirect_uri'); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRedirectUri); })(renderArgs[2]);
            });
        });
      }

      describe('login state specific', () => {
        const fixture9 = Object.create(fixture5);

        before(() => fixture9.login(), { timeout: 3000 });

        it('malformed id_token_hint', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture9.provider.once('authorization.error', spy);
          const auth = new fixture9.AuthorizationRequest({
            response_type,
            scope,
            id_token_hint: 'invalid',
          });

          return fixture9.wrap({ route, verb, auth })
            .expect(303)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_request'))
            .expect(auth.validateErrorDescription(/could not validate id_token_hint/));
        });
      });
    });
  });
});
