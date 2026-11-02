import { describe, before, after, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseLocation } from 'node:url';
import { createPrivateKey } from 'node:crypto';

import get from 'lodash/get.js';
import sinon from 'sinon';

import { decode as decodeJWT, sign as signJWT } from '../../lib/helpers/jwt.js';
import { InvalidRequest } from '../../lib/helpers/errors.js';
import bootstrap from '../test_helper.js';
import keys from '../keys.js';

const route = '/auth';
const expire = new Date();

expire.setDate(expire.getDate() + 1);
['get', 'post'].forEach((verb) => {
  describe(`claimsParameter via ${verb} ${route}`, () => {
    const fixture = {};

    before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

    describe('specify id_token', () => {
      const fixture1 = Object.create(fixture);

      before(() => fixture1.login({
          claims: {
            id_token: {
              email: { constructor: null },
              middle_name: {},
            },
          },
        }), { timeout: 3000 });
      after(() => fixture1.logout(), { timeout: 3000 });

      it('should return individual claims requested', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: {
            id_token: {
              email: null,
              middle_name: {},
            },
          },
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            assert.ok(['email', 'middle_name'].every((key) => Object.keys(payload).includes(key)));
            assert.notDeepEqual(new Set(Object.keys(payload)), new Set(['preferred_username', 'picture', 'website']));
          });
      });

      it('accepts constructor-named JSON object members', { timeout: 3000 }, () => {
        const auth = new fixture1.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          max_age: 3600,
          claims: JSON.stringify({
            constructor: null,
            id_token: {
              constructor: null,
              email: { constructor: null },
            },
          }),
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            assert.ok(['auth_time', 'email'].every((key) => Object.keys(payload).includes(key)));
          });
      });
    });

    describe('with acr_values on the client', () => {
      const fixture2 = Object.create(fixture);

      before(() => fixture2.login(), { timeout: 3000 });
      after(() => fixture2.logout(), { timeout: 3000 });

      before(async () => {
        const client = await fixture2.provider.Client.find('client');
        client.defaultAcrValues = ['1', '2'];
      }, { timeout: 3000 });

      after(async () => {
        const client = await fixture2.provider.Client.find('client');
        delete client.defaultAcrValues;
      }, { timeout: 3000 });

      it('(pre 4.x behavior backfill) should include the acr claim now', { timeout: 3000 }, () => {
        const descriptor = Object.getOwnPropertyDescriptor(fixture2.provider.OIDCContext.prototype, 'acr');

        Object.defineProperty(fixture2.provider.OIDCContext.prototype, 'acr', {
          get() {
            return get(this, 'result.login.acr', '0');
          },
        });

        const auth = new fixture2.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
        });

        return fixture2.wrap({ route, verb, auth })
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            assert.ok(['acr'].every((key) => Object.keys(payload).includes(key)));
            Object.defineProperty(fixture2.provider.OIDCContext.prototype, 'acr', descriptor);
          })
          .catch((err) => {
            Object.defineProperty(fixture2.provider.OIDCContext.prototype, 'acr', descriptor);
            throw err;
          });
      });
    });

    describe('specify userinfo', () => {
      const fixture3 = Object.create(fixture);

      before(() => fixture3.login({
          claims: {
            id_token: {
              email: null,
              middle_name: {},
            },
          },
        }), { timeout: 3000 });
      after(() => fixture3.logout(), { timeout: 3000 });

      it('should return individual claims requested', { timeout: 3000 }, (_t, done) => {
        const auth = new fixture3.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: {
            userinfo: {
              email: { constructor: null },
              middle_name: {},
            },
          },
        });

        fixture3.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['access_token', 'scope'], false))
          .end((err, response) => {
            if (err) {
              return done(err);
            }

            const { query: { access_token } } = parseLocation(response.headers.location, true);
            return fixture3.agent
              .get('/me')
              .auth(access_token, { type: 'bearer' })
              .expect(200)
              .expect(({ body }) => {
                assert.ok(['email', 'middle_name'].every((key) => Object.keys(body).includes(key)));
                assert.notDeepEqual(new Set(Object.keys(body)), new Set(['preferred_username', 'picture', 'website']));
              })
              .end(done);
          });
      });
    });

    describe('specify both id_token and userinfo', () => {
      const fixture4 = Object.create(fixture);

      before(() => fixture4.login({
          claims: {
            id_token: {
              email: null,
            },
            userinfo: {
              given_name: null,
            },
          },
        }), { timeout: 3000 });
      after(() => fixture4.logout(), { timeout: 3000 });

      it('should return individual claims requested', { timeout: 3000 }, (_t, done) => {
        const auth = new fixture4.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: {
            id_token: {
              email: null,
            },
            userinfo: {
              given_name: null,
            },
          },
        });

        fixture4.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'access_token', 'scope'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            assert.ok(['email'].every((key) => Object.keys(payload).includes(key)));
            assert.notDeepEqual(new Set(Object.keys(payload)), new Set(['given_name']));
          })
          .end((_err, response) => {
            const { query: { access_token } } = parseLocation(response.headers.location, true);
            fixture4.agent
              .get('/me')
              .auth(access_token, { type: 'bearer' })
              .expect(200)
              .expect((userinfo) => {
                assert.ok(['given_name'].every((key) => Object.keys(userinfo.body).includes(key)));
                assert.notDeepEqual(new Set(Object.keys(userinfo.body)), new Set(['email']));
              })
              .end(done);
          });
      });
    });

    describe('related interactions', () => {
      const fixture5 = Object.create(fixture);

      beforeEach(() => fixture5.login(), { timeout: 3000 });
      afterEach(() => fixture5.logout(), { timeout: 3000 });
      describe('are met', () => {
        const fixture6 = Object.create(fixture5);

        function setup(grant, result) {
          const cookies = [];

          const sess = new this.provider.Interaction('resume', { uid: 'resume' });
          if (grant) {
            const cookie = `_interaction_resume=resume; path=${this.suitePath('/auth/resume')}; expires=${expire.toGMTString()}; httponly`;
            cookies.push(cookie);
            Object.assign(sess, { params: grant });
          }

          if (result) {
            Object.assign(sess, { result });
          }

          this.agent._saveCookies.bind(this.agent)({
            request: { url: this.provider.issuer },
            headers: { 'set-cookie': cookies },
          });

          return sess.save(30); // TODO: bother running the ttl helper?
        }

        it('session subject value differs from the one requested [1/2]', { timeout: 3000 }, () => {
          const session = fixture6.getSession();
          const auth = new fixture6.AuthorizationRequest({
            client_id: 'client',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: session.accountId,
                },
              },
            },
          });

          return fixture6.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });

        it('session subject value differs from the one requested [2/2]', { timeout: 3000 }, () => {
          const session = fixture6.getSession();
          const auth = new fixture6.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: `${session.accountId}-pairwise`,
                },
              },
            },
          });

          return fixture6.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });

        if (verb === 'get') {
          it('none of multiple authentication context class references requested are met', { timeout: 3000 }, () => {
            const auth = new fixture6.AuthorizationRequest({
              response_type: 'id_token',
              response_mode: 'fragment',
              scope: 'openid',
              prompt: 'none',
              claims: {
                id_token: {
                  acr: {
                    essential: true,
                    values: ['1', '2'],
                  },
                },
              },
            });

            setup.call(fixture6, auth, {
              login: {
                accountId: fixture6.loggedInAccountId,
                acr: '2',
              },
            });

            return fixture6.wrap({ route: `${route}/resume`, verb, auth })
              .expect(303)
              .expect(auth.validateFragment)
              .expect(auth.validatePresence(['id_token', 'state']))
              .expect(auth.validateState)
              .expect(auth.validateClientLocation);
          });

          it('single requested authentication context class reference is not met', { timeout: 3000 }, () => {
            const auth = new fixture6.AuthorizationRequest({
              response_type: 'id_token',
              response_mode: 'fragment',
              scope: 'openid',
              prompt: 'none',
              claims: {
                id_token: {
                  acr: {
                    essential: true,
                    value: '1',
                  },
                },
              },
            });

            setup.call(fixture6, auth, {
              login: {
                accountId: fixture6.loggedInAccountId,
                acr: '1',
              },
            });

            return fixture6.wrap({ route: `${route}/resume`, verb, auth })
              .expect(303)
              .expect(auth.validateFragment)
              .expect(auth.validatePresence(['id_token', 'state']))
              .expect(auth.validateState)
              .expect(auth.validateClientLocation);
          });
        }
      });

      describe('are not met', () => {
        const fixture7 = Object.create(fixture5);

        it('session subject value differs from the one requested [1/3]', { timeout: 3000 }, () => {
          const auth = new fixture7.AuthorizationRequest({
            client_id: 'client',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: 'iexpectthisid',
                },
              },
            },
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('requested subject could not be obtained'));
        });

        it('session subject value differs from the one requested [2/3]', { timeout: 3000 }, () => {
          const auth = new fixture7.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: 'iexpectthisid-pairwise',
                },
              },
            },
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('requested subject could not be obtained'));
        });

        it('session subject value differs from the one requested [3/3]', { timeout: 3000 }, () => {
          fixture7.logout();
          const auth = new fixture7.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            claims: {
              id_token: {
                sub: {
                  value: 'iexpectthisid-pairwise',
                },
              },
            },
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateInteractionRedirect)
            .expect(auth.validateInteraction('login', 'claims_id_token_sub_value', 'no_session'));
        });

        it('none of multiple authentication context class references requested are met (1/2)', { timeout: 3000 }, () => {
          const auth = new fixture7.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                acr: {
                  essential: true,
                  values: ['1', '2'],
                },
              },
            },
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('none of the requested ACRs could be obtained'));
        });

        it('none of multiple authentication context class references requested are met (2/2)', { timeout: 3000 }, () => {
          const auth = new fixture7.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                acr: {
                  essential: true,
                  values: 'foo',
                },
              },
            },
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_request'))
            .expect(auth.validateErrorDescription('invalid claims.id_token.acr.values type'));
        });

        it('single requested authentication context class reference is not met', { timeout: 3000 }, () => {
          const auth = new fixture7.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                acr: {
                  essential: true,
                  value: '1',
                },
              },
            },
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('requested ACR could not be obtained'));
        });

        it('additional claims are requested', { timeout: 3000 }, () => {
          const auth = new fixture7.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: { family_name: null },
            },
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('consent_required'))
            .expect(auth.validateErrorDescription('requested claims not granted'));
        });

        it('rejects an id_token_hint aud array containing a non-string member', { timeout: 3000 }, async () => {
          const hint = await signJWT({
            aud: ['client', null],
            exp: Math.floor(Date.now() / 1000) + 3600,
            iss: fixture7.provider.issuer,
            sub: fixture7.loggedInAccountId,
          }, createPrivateKey({ format: 'jwk', key: keys[0] }), 'RS256');

          const auth = new fixture7.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint,
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_request'))
            .expect(auth.validateErrorDescription('could not validate id_token_hint'));
        });

        it('id_token_hint belongs to a user that is not currently logged in [1/3]', { timeout: 3000 }, async () => {
          const client = await fixture7.provider.Client.find('client');
          const { IdToken } = fixture7.provider;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for',
          }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new fixture7.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint,
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('id_token_hint and authenticated subject do not match'));
        });

        it('id_token_hint belongs to a user that is not currently logged in [2/3]', { timeout: 3000 }, async () => {
          const client = await fixture7.provider.Client.find('client-pairwise');
          const { IdToken } = fixture7.provider;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for',
          }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new fixture7.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint,
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('id_token_hint and authenticated subject do not match'));
        });

        it('id_token_hint belongs to a user that is not currently logged in [3/3]', { timeout: 3000 }, async () => {
          fixture7.logout();
          const client = await fixture7.provider.Client.find('client-pairwise');
          const { IdToken } = fixture7.provider;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for',
          }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new fixture7.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            id_token_hint: hint,
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateInteractionRedirect)
            .expect(auth.validateInteraction('login', 'id_token_hint', 'no_session'));
        });

        it('id_token_hint belongs to a user that is currently logged in [1/2]', { timeout: 3000 }, async () => {
          const session = fixture7.getSession();
          const client = await fixture7.provider.Client.find('client');
          const { IdToken } = fixture7.provider;
          const idToken = new IdToken({ sub: session.accountId }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new fixture7.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint,
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });

        it('id_token_hint belongs to a user that is currently logged in [2/2]', { timeout: 3000 }, async () => {
          const session = fixture7.getSession();
          const client = await fixture7.provider.Client.find('client-pairwise');
          const { IdToken } = fixture7.provider;
          const idToken = new IdToken({ sub: session.accountId }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new fixture7.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint,
          });

          return fixture7.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });
      });
    });

    describe('custom claims validation', () => {
      const fixture8 = Object.create(fixture);

      let assertion;

      beforeEach(() => {
        assertion = sinon.stub(i(fixture8.provider).features.claimsParameter, 'assertClaimsParameter').resolves();
      }, { timeout: 3000 });

      afterEach(() => assertion.restore(), { timeout: 3000 });

      for (const container of ['userinfo', 'id_token']) {
        it(`can accept verified_claims arrays in claims.${container}`, { timeout: 3000 }, async () => {
          const claims = {
            [container]: {
              verified_claims: [{
                verification: { trust_framework: { value: 'eidas' } },
                claims: { given_name: null, family_name: null },
              }],
            },
          };
          const auth = new fixture8.AuthorizationRequest({
            response_type: 'id_token token',
            scope: 'openid',
            claims,
          });

          await fixture8.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateInteractionRedirect);

          assert.equal(assertion.calledOnce, true);
          const [ctx, parsedClaims, client] = assertion.firstCall.args;
          assert.deepEqual(parsedClaims, claims);
          assert.equal(client, ctx.oidc.client);
        });
      }

      it('can reject claims with a custom error', { timeout: 3000 }, async () => {
        assertion.rejects(new InvalidRequest('custom claims validation failed'));
        const auth = new fixture8.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: { id_token: { email: null } },
        });

        await fixture8.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('custom claims validation failed'));

        assert.equal(assertion.calledOnce, true);
      });

      for (const [claims, description] of [
        [[], 'claims parameter should be a JSON object'],
        [{ userinfo: [] }, 'claims.userinfo should be an object'],
        [{ id_token: [] }, 'claims.id_token should be an object'],
      ]) {
        it(`still enforces that ${description}`, { timeout: 3000 }, async () => {
          const auth = new fixture8.AuthorizationRequest({
            response_type: 'id_token token',
            scope: 'openid',
            claims: JSON.stringify(claims),
          });

          await fixture8.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validateError('invalid_request'))
            .expect(auth.validateErrorDescription(description));

          assert.equal(assertion.called, false);
        });
      }
    });

    describe('parameter validations', () => {
      const fixture9 = Object.create(fixture);

      it('should not be combined with response_type=none', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'none',
          scope: 'openid',
          claims: 'something',
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims parameter should not be combined with response_type none'));
      });

      it('should handle when invalid json is provided', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: 'something',
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('could not parse the claims parameter JSON'));
      });

      it('should validate an object is passed', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: 'true',
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims parameter should be a JSON object'));
      });

      it('should check accepted properties being present', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"not_recognized": "does not matter"}',
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims parameter should have userinfo or id_token properties'));
      });

      it('should check userinfo property being a simple object', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"userinfo": "Not an Object"}',
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.userinfo should be an object'));
      });

      it('should check id_token property being a simple object', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"id_token": "Not an Object"}',
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.id_token should be an object'));
      });

      for (const container of ['userinfo', 'id_token']) {
        for (const [type, value] of [
          ['string', 'invalid'],
          ['boolean', false],
          ['number', 0],
          ['array', []],
        ]) {
          it(`rejects ${type} members in claims.${container}`, { timeout: 3000 }, () => {
            const auth = new fixture9.AuthorizationRequest({
              response_type: 'id_token token',
              scope: 'openid',
              claims: {
                [container]: {
                  email: value,
                },
              },
            });

            return fixture9.wrap({ route, verb, auth })
              .expect(303)
              .expect(auth.validateFragment)
              .expect(auth.validatePresence(['error', 'error_description', 'state']))
              .expect(auth.validateState)
              .expect(auth.validateClientLocation)
              .expect(auth.validateError('invalid_request'))
              .expect(auth.validateErrorDescription(`claims.${container} members must be null or objects`));
          });
        }
      }

      it('validates individual claim shapes before response type restrictions', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
          claims: { userinfo: { email: [] } },
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.userinfo members must be null or objects'));
      });

      it('does not reflect invalid individual claim names in errors', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: {
            id_token: Object.fromEntries([['"\\\r\n', false]]),
          },
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.id_token members must be null or objects'));
      });

      describe('when userinfo is disabled', () => {
        const fixture10 = Object.create(fixture9);

        before(() => {
          i(fixture10.provider).features.userinfo.enabled = false;
        }, { timeout: 3000 });

        after(() => {
          i(fixture10.provider).features.userinfo.enabled = true;
        }, { timeout: 3000 });

        it('should not accept userinfo as a property', { timeout: 3000 }, () => {
          const auth = new fixture10.AuthorizationRequest({
            response_type: 'id_token token',
            scope: 'openid',
            claims: {
              userinfo: {
                email: null,
                middle_name: {},
              },
            },
          });

          return fixture10.wrap({ route, verb, auth })
            .expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_request'))
            .expect(auth.validateErrorDescription('claims.userinfo should not be used since userinfo endpoint is not supported'));
        });
      });

      it('should check that userinfo claims are not specified for id_token requests', { timeout: 3000 }, () => {
        const auth = new fixture9.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
          claims: '{"userinfo": {}}',
        });

        return fixture9.wrap({ route, verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.userinfo should not be used if access_token is not issued'));
      });
    });
  });
});
