import { describe, before, afterEach, it, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseUrl } from 'node:url';
import { randomBytes } from 'node:crypto';

import { createSandbox } from 'sinon';
import timekeeper from 'timekeeper';

import bootstrap from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.js';
import { InvalidClient, InvalidRequest } from '../../lib/helpers/errors.js';

const sinon = createSandbox();

const route = '/session/end';

describe('logout endpoint', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  afterEach(() => timekeeper.reset(), { timeout: 3000 });

  describe('when logged out', () => {
    const fixture1 = Object.create(fixture);

    ['get', 'post'].forEach((verb) => {
      describe(`${verb.toUpperCase()} end_session`, () => {
        const fixture2 = Object.create(fixture1);

        it('autosubmits the confirmation form', { timeout: 3000 }, () => fixture2.wrap({ route, verb })
            .expect(200)
            .expect(({ text: body }) => {
              const { state } = fixture2.getSession();

              assert.ok(state.secret);
              assert.equal(state.postLogoutRedirectUri, undefined);

              assert.ok(body.includes(`input type="hidden" name="xsrf" value="${state.secret}"`));
              assert.ok(body.includes(`form method="post" action="${fixture2.provider.issuer}${fixture2.suitePath('/session/end/confirm')}"`));
            }));
      });
    });
  });

  describe('when logged in', () => {
    const fixture3 = Object.create(fixture);

    beforeEach(() => fixture3.login(), { timeout: 3000 });
    afterEach(() => fixture3.logout(), { timeout: 3000 });
    afterEach(() => sinon.restore(), { timeout: 3000 });

    beforeEach(() => fixture3.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid',
          nonce: randomBytes(16).toString('base64url'),
          response_type: 'id_token',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(303)
        .expect((response) => {
          const { query: { id_token: idToken } } = parseUrl(response.headers.location.replace('#', '?'), true);
          fixture3.idToken = idToken;
        }), { timeout: 3000 });

    ['get', 'post'].forEach((verb) => {
      describe(`${verb.toUpperCase()} end_session`, () => {
        const fixture4 = Object.create(fixture3);

        describe('client with postLogoutRedirectUris', () => {
          const fixture5 = Object.create(fixture4);

          before(async () => {
            (await fixture5.provider.Client.find('client')).postLogoutRedirectUris = ['https://client.example.com/logout/cb'];
          }, { timeout: 3000 });
          after(async () => {
            (await fixture5.provider.Client.find('client')).postLogoutRedirectUris = [];
          }, { timeout: 3000 });

          it('even when expired', { timeout: 3000 }, () => {
            timekeeper.travel(Date.now() + ((3600 + 10) * 1000));
            const params = {
              id_token_hint: fixture5.idToken,
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            };

            return fixture5.wrap({ route, verb, params })
              .expect(200)
              .expect(() => {
                const { state: { postLogoutRedirectUri } } = fixture5.getSession();
                assert.equal(postLogoutRedirectUri, 'https://client.example.com/logout/cb');
              });
          });

          it('allows to redirect there (with id_token_hint)', { timeout: 3000 }, () => {
            const params = {
              id_token_hint: fixture5.idToken,
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            };

            return fixture5.wrap({ route, verb, params })
              .expect(200)
              .expect(() => {
                const { state: { postLogoutRedirectUri } } = fixture5.getSession();
                assert.equal(postLogoutRedirectUri, 'https://client.example.com/logout/cb');
              });
          });

          it('allows to redirect there (with client_id)', { timeout: 3000 }, () => {
            const params = {
              client_id: 'client',
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            };

            return fixture5.wrap({ route, verb, params })
              .expect(200)
              .expect(() => {
                const { state: { postLogoutRedirectUri } } = fixture5.getSession();
                assert.equal(postLogoutRedirectUri, 'https://client.example.com/logout/cb');
              });
          });

          for (const post_logout_redirect_uri of [
            'https://client.example.com:443/logout/cb',
            'https://CLIENT.EXAMPLE.COM/logout/cb',
          ]) {
            it(`requires exact post_logout_redirect_uri matching (${post_logout_redirect_uri})`, { timeout: 3000 }, () => {
              const params = {
                client_id: 'client',
                post_logout_redirect_uri,
              };

              const emitSpy = sinon.spy();
              const renderSpy = sinon.spy(i(fixture5.provider).configuration, 'renderError');
              fixture5.provider.once('end_session.error', emitSpy);

              return fixture5.wrap({ route, verb, params })
                .set('Accept', 'text/html')
                .expect(400)
                .expect(() => {
                  assert.equal(emitSpy.calledOnce, true);
                  assert.equal(renderSpy.calledOnce, true);
                  const renderArgs = renderSpy.args[0];
                  ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
                  ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'post_logout_redirect_uri not registered'); })(renderArgs[1]);
                  ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
                });
            });
          }

          it('allows to redirect there (with id_token_hint and client_id)', { timeout: 3000 }, () => {
            const params = {
              client_id: 'client',
              id_token_hint: fixture5.idToken,
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            };

            return fixture5.wrap({ route, verb, params })
              .expect(200)
              .expect(() => {
                const { state: { postLogoutRedirectUri } } = fixture5.getSession();
                assert.equal(postLogoutRedirectUri, 'https://client.example.com/logout/cb');
              });
          });

          it('requires client_id to match the id_token_hint', { timeout: 3000 }, () => {
            const params = {
              client_id: 'client2',
              id_token_hint: fixture5.idToken,
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            };

            const emitSpy = sinon.spy();
            const renderSpy = sinon.spy(i(fixture5.provider).configuration, 'renderError');
            fixture5.provider.once('end_session.error', emitSpy);

            return fixture5.wrap({ route, verb, params })
              .set('Accept', 'text/html')
              .expect(400)
              .expect(() => {
                assert.equal(emitSpy.calledOnce, true);
                assert.equal(renderSpy.calledOnce, true);
                const renderArgs = renderSpy.args[0];
                ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
                ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'client_id does not match the provided id_token_hint'); })(renderArgs[1]);
                ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
              });
          });

          it('requires client_id to be valid', { timeout: 3000 }, () => {
            const params = {
              client_id: 'client2',
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            };

            const emitSpy = sinon.spy();
            const renderSpy = sinon.spy(i(fixture5.provider).configuration, 'renderError');
            fixture5.provider.once('end_session.error', emitSpy);

            return fixture5.wrap({ route, verb, params })
              .set('Accept', 'text/html')
              .expect(400)
              .expect(() => {
                assert.equal(emitSpy.calledOnce, true);
                assert.equal(renderSpy.calledOnce, true);
                const renderArgs = renderSpy.args[0];
                ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client'); })(renderArgs[1]);
                ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'client is invalid'); })(renderArgs[1]);
                ((actual) => { assert.ok(actual instanceof InvalidClient); })(renderArgs[2]);
              });
          });

          describe('expired client secrets', () => {
            const fixture6 = Object.create(fixture5);

            after(async () => {
              const client = await fixture6.provider.Client.find('client-hmac');
              client.clientSecretExpiresAt = 0;
            }, { timeout: 3000 });

            it('rejects HMAC hints if the secret is expired', { timeout: 3000 }, async () => {
              const client = await fixture6.provider.Client.find('client-hmac');

              let idToken;

              await fixture6.agent.get('/auth')
                .query({
                  client_id: 'client-hmac',
                  scope: 'openid',
                  nonce: randomBytes(16).toString('base64url'),
                  response_type: 'id_token',
                  redirect_uri: 'https://client.example.com/cb',
                })
                .expect(303)
                .expect((response) => {
                  ({ query: { id_token: idToken } } = parseUrl(response.headers.location.replace('#', '?'), true));
                });

              client.clientSecretExpiresAt = 1;

              const params = {
                id_token_hint: idToken,
                post_logout_redirect_uri: 'https://client.example.com/logout/cb',
              };

              const emitSpy = sinon.spy();
              const renderSpy = sinon.spy(i(fixture6.provider).configuration, 'renderError');
              fixture6.provider.once('end_session.error', emitSpy);

              return fixture6.wrap({ route, verb, params })
                .set('Accept', 'text/html')
                .expect(() => {
                  renderSpy.restore();
                })
                .expect(400)
                .expect(() => {
                  assert.equal(emitSpy.calledOnce, true);
                  assert.equal(renderSpy.calledOnce, true);
                  const renderArgs = renderSpy.args[0];
                  ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client'); })(renderArgs[1]);
                  ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'client secret is expired - cannot validate ID Token Hint'); })(renderArgs[1]);
                  ((actual) => { assert.ok(actual instanceof InvalidClient); })(renderArgs[2]);
                });
            });
          });

          it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
            fixture5.assertOnce((ctx) => {
              assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'IdTokenHint', 'Session']));
            }, done);

            const params = {
              id_token_hint: fixture5.idToken,
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
            };

            fixture5.wrap({ route, verb, params })
              .end(() => {});
          });

          it('also forwards the state if provided', { timeout: 3000 }, () => {
            const params = {
              id_token_hint: fixture5.idToken,
              post_logout_redirect_uri: 'https://client.example.com/logout/cb',
              state: 'foobar',
            };

            return fixture5.wrap({ route, verb, params })
              .expect(200)
              .expect(() => {
                const { state: { postLogoutRedirectUri, state } } = fixture5.getSession();
                assert.equal(postLogoutRedirectUri, 'https://client.example.com/logout/cb');
                assert.equal(state, 'foobar');
              });
          });

          it('can omit the post_logout_redirect_uri and uses the default one', { timeout: 3000 }, () => {
            const params = { id_token_hint: fixture5.idToken };

            return fixture5.wrap({ route, verb, params })
              .expect(200)
              .expect(() => {
                const { state: { postLogoutRedirectUri } } = fixture5.getSession();
                assert.equal(postLogoutRedirectUri, undefined);
              });
          });

          it('ignores unverified post_logout_redirect_uri', { timeout: 3000 }, () => {
            const params = { post_logout_redirect_uri: 'https://client.example.com/logout/cb' };

            return fixture5.wrap({ route, verb, params })
              .expect(200)
              .expect(() => {
                const { state: { postLogoutRedirectUri } } = fixture5.getSession();
                assert.equal(postLogoutRedirectUri, undefined);
              });
          });
        });

        it('validates post_logout_redirect_uri allowed on client', { timeout: 3000 }, () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture4.provider).configuration, 'renderError');
          fixture4.provider.once('end_session.error', emitSpy);
          const params = {
            id_token_hint: fixture4.idToken,
            post_logout_redirect_uri: 'https://client.example.com/callback/logout',
          };

          return fixture4.agent.get(route)
            .set('Accept', 'text/html')
            .query(params)
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'post_logout_redirect_uri not registered'); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
            });
        });

        it('rejects invalid JWTs', { timeout: 3000 }, () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture4.provider).configuration, 'renderError');
          fixture4.provider.once('end_session.error', emitSpy);
          const params = {
            id_token_hint: 'not.a.jwt',
          };

          return fixture4.agent.get(route)
            .set('Accept', 'text/html')
            .query(params)
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /could not decode id_token_hint/); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
            });
        });

        it('rejects an id_token_hint whose payload is not a JSON object', { timeout: 3000 }, async () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture4.provider).configuration, 'renderError');
          fixture4.provider.once('end_session.error', emitSpy);
          const id_token_hint = [
            Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url'),
            Buffer.from('null').toString('base64url'),
            'invalid-signature',
          ].join('.');

          let request = fixture4.agent[verb](route)
            .set('Accept', 'text/html');
          if (verb === 'get') {
            request = request.query({ id_token_hint });
          } else {
            request = request.type('form').send({ id_token_hint });
          }

          return request
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not decode id_token_hint'); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
            });
        });

        it('rejects JWTs with unrecognized client', { timeout: 3000 }, async () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture4.provider).configuration, 'renderError');
          fixture4.provider.once('end_session.error', emitSpy);
          const params = {
            id_token_hint: await JWT.sign({
              aud: 'nonexistant',
              iss: fixture4.provider.issuer,
            }, Buffer.from('secret'), 'HS256'),
          };

          return fixture4.agent.get(route)
            .set('Accept', 'text/html')
            .query(params)
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client'); })(renderArgs[1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'unrecognized id_token_hint audience'); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidClient); })(renderArgs[2]);
            });
        });

        it('rejects JWTs with bad signatures', { timeout: 3000 }, async () => {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(fixture4.provider).configuration, 'renderError');
          fixture4.provider.once('end_session.error', emitSpy);
          const params = {
            id_token_hint: await JWT.sign({
              aud: 'client',
              iss: fixture4.provider.issuer,
            }, Buffer.from('not THE secret'), 'HS256'),
          };

          return fixture4.agent.get(route)
            .set('Accept', 'text/html')
            .query(params)
            .expect(400)
            .expect(() => {
              assert.equal(emitSpy.calledOnce, true);
              assert.equal(renderSpy.calledOnce, true);
              const renderArgs = renderSpy.args[0];
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /could not validate id_token_hint/); })(renderArgs[1]);
              ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
            });
        });
      });
    });

    describe('POST end_session_confirm', () => {
      const fixture7 = Object.create(fixture3);

      it('checks session.state is set', { timeout: 3000 }, () => {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(fixture7.provider).configuration, 'renderError');
        fixture7.provider.once('end_session_confirm.error', emitSpy);
        return fixture7.agent.post('/session/end/confirm')
          .set('Accept', 'text/html')
          .send({})
          .type('form')
          .expect(400)
          .expect(() => {
            assert.equal(emitSpy.calledOnce, true);
            assert.equal(renderSpy.calledOnce, true);
            const renderArgs = renderSpy.args[0];
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not find logout details'); })(renderArgs[1]);
            ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
          });
      });

      it('checks session.state.secret (xsrf is right)', { timeout: 3000 }, () => {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(fixture7.provider).configuration, 'renderError');
        fixture7.provider.once('end_session_confirm.error', emitSpy);
        fixture7.getSession().state = { secret: '123' };

        return fixture7.agent.post('/session/end/confirm')
          .set('Accept', 'text/html')
          .send({ xsrf: 'not right' })
          .type('form')
          .expect(400)
          .expect(() => {
            assert.equal(emitSpy.calledOnce, true);
            assert.equal(renderSpy.calledOnce, true);
            const renderArgs = renderSpy.args[0];
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'xsrf token invalid'); })(renderArgs[1]);
            ((actual) => { assert.ok(actual instanceof InvalidRequest); })(renderArgs[2]);
          });
      });

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture7.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Session']));
        }, done);

        fixture7.getSession().state = { secret: '123', postLogoutRedirectUri: 'https://rp.example.com/', clientId: 'client' };

        fixture7.agent.post('/session/end/confirm')
          .send({ xsrf: '123', logout: 'yes' })
          .type('form')
          .end(() => {});
      });

      it('destroys complete session if user wants to', { timeout: 3000 }, () => {
        const sessionId = fixture7.getSessionId();
        const sessionAdapter = fixture7.TestAdapter.for('Session');
        sinon.spy(sessionAdapter, 'destroy');
        sinon.spy(sessionAdapter, 'upsert');
        const authorizationCodeAdapter = fixture7.TestAdapter.for('AuthorizationCode');
        sinon.spy(authorizationCodeAdapter, 'revokeByGrantId');
        const session = fixture7.getSession();

        session.state = { secret: '123', postLogoutRedirectUri: 'https://rp.example.com/', clientId: 'client' };
        session.authorizations.client.persistsLogout = true;

        const [firstGrant, secondGrant] = Object.keys(session.authorizations)
          .map((x) => session.authorizations[x].grantId);

        return fixture7.agent.post('/session/end/confirm')
          .send({ xsrf: '123', logout: 'yes' })
          .type('form')
          .expect(303)
          .expect((response) => {
            assert.equal(sessionAdapter.destroy.called, true);
            assert.notEqual(sessionAdapter.upsert.called, true);
            assert.equal(sessionAdapter.destroy.withArgs(sessionId).calledOnce, true);
            assert.ok(!('client_id' in Object(parseUrl(response.headers.location, true).query)));
            assert.equal(authorizationCodeAdapter
              .revokeByGrantId.calledOnce, true);
            assert.equal(authorizationCodeAdapter
              .revokeByGrantId.withArgs(firstGrant).calledOnce, false);
            assert.equal(authorizationCodeAdapter
              .revokeByGrantId.withArgs(secondGrant).calledOnce, true);
          });
      });

      it('only clears one clients session if user doesn\'t want to log out (using post_logout_redirect_uri)', { timeout: 3000 }, () => {
        const adapter = fixture7.TestAdapter.for('Session');
        sinon.spy(adapter, 'destroy');
        const authorizationCodeAdapter = fixture7.TestAdapter.for('AuthorizationCode');
        sinon.spy(authorizationCodeAdapter, 'revokeByGrantId');
        let session = fixture7.getSession();
        const oldId = fixture7.getSessionId();
        session.state = { secret: '123', postLogoutRedirectUri: 'https://rp.example.com/logout/cb', clientId: 'client' };
        session.authorizations.client.persistsLogout = true;

        assert.ok(session.authorizations.client);

        return fixture7.agent.post('/session/end/confirm')
          .send({ xsrf: '123' })
          .type('form')
          .expect(303)
          .expect((response) => {
            session = fixture7.getSession();
            assert.equal(session.authorizations.client, undefined);
            assert.equal(session.state, undefined);
            assert.notDeepEqual(fixture7.getSessionId(), oldId);
            assert.equal(adapter.destroy.calledOnceWith(oldId), true);
            assert.notDeepEqual(new Set(Object.keys(parseUrl(response.headers.location, true).query)), new Set(['client_id']));
            assert.equal(authorizationCodeAdapter
              .revokeByGrantId.called, false);
          });
      });

      it('only clears one clients session if user doesn\'t want to log out (using end_session_success)', { timeout: 3000 }, () => {
        const adapter = fixture7.TestAdapter.for('Session');
        sinon.spy(adapter, 'destroy');
        let session = fixture7.getSession();
        const oldId = fixture7.getSessionId();
        session.state = { secret: '123', clientId: 'client' };

        assert.ok(session.authorizations.client);

        return fixture7.agent.post('/session/end/confirm')
          .send({ xsrf: '123' })
          .type('form')
          .expect(303)
          .expect((response) => {
            session = fixture7.getSession();
            assert.equal(session.authorizations.client, undefined);
            assert.equal(session.state, undefined);
            assert.notDeepEqual(fixture7.getSessionId(), oldId);
            assert.equal(adapter.destroy.calledOnceWith(oldId), true);
            ((actual) => { assert.ok('client_id' in Object(actual)); assert.equal(actual.client_id, 'client'); })(parseUrl(response.headers.location, true).query);
          });
      });

      it('clears one clients session when the client can no longer be resolved', { timeout: 3000 }, () => {
        const find = sinon.stub(fixture7.provider.Client, 'find').callsFake(async function clientFind(clientId) {
          if (clientId === 'client') {
            throw new InvalidClient('client is invalid', 'client not found');
          }

          return find.wrappedMethod.call(this, clientId);
        });

        let session = fixture7.getSession();
        const oldId = fixture7.getSessionId();
        session.state = { secret: '123', clientId: 'client' };

        assert.ok(session.authorizations.client);

        return fixture7.agent.post('/session/end/confirm')
          .send({ xsrf: '123' })
          .type('form')
          .expect(303)
          .expect((response) => {
            find.restore();
            session = fixture7.getSession();
            assert.equal(session.authorizations.client, undefined);
            assert.equal(session.state, undefined);
            assert.notDeepEqual(fixture7.getSessionId(), oldId);
            ((actual) => { assert.ok('client_id' in Object(actual)); assert.equal(actual.client_id, 'client'); })(parseUrl(response.headers.location, true).query);
          });
      });

      it('forwards the state too', { timeout: 3000 }, () => {
        fixture7.getSession().state = {
          secret: '123', postLogoutRedirectUri: 'https://rp.example.com/', clientId: 'client', state: 'foobar',
        };

        i(fixture7.provider).configuration.cookies.long.domain = '.oidc.dev';

        return fixture7.agent.post('/session/end/confirm')
          .send({ xsrf: '123', logout: 'yes' })
          .type('form')
          .expect(() => {
            delete i(fixture7.provider).configuration.cookies.long.domain;
          })
          .expect(303)
          .expect('location', 'https://rp.example.com/?state=foobar');
      });

      it('handles a no existing session state', { timeout: 3000 }, async () => {
        Object.assign(fixture7.getSession(), {
          state: {
            secret: '123', postLogoutRedirectUri: 'https://rp.example.com/', clientId: 'client', state: 'foobar',
          },
          authorizations: undefined,
        });

        return fixture7.agent.post('/session/end/confirm')
          .send({ xsrf: '123' })
          .type('form')
          .expect(() => {
            delete i(fixture7.provider).configuration.cookies.long.domain;
          })
          .expect(303);
      });
    });

    describe('GET end_session_success', () => {
      const fixture8 = Object.create(fixture3);

      it('calls the postLogoutSuccessSource helper', { timeout: 3000 }, () => {
        const renderSpy = sinon.spy(i(fixture8.provider).features.rpInitiatedLogout, 'postLogoutSuccessSource');
        return fixture8.agent.get('/session/end/success')
          .set('Accept', 'text/html')
          .expect(200)
          .expect(() => {
            assert.equal(renderSpy.calledOnce, true);
            const [ctx] = renderSpy.args[0];
            assert.equal(ctx.oidc.client, undefined);
          });
      });

      it('has the client loaded when present', { timeout: 3000 }, () => {
        const renderSpy = sinon.spy(i(fixture8.provider).features.rpInitiatedLogout, 'postLogoutSuccessSource');
        return fixture8.agent.get('/session/end/success?client_id=client')
          .set('Accept', 'text/html')
          .expect(200)
          .expect(() => {
            assert.equal(renderSpy.calledOnce, true);
            const [ctx] = renderSpy.args[0];
            assert.ok(ctx.oidc.client);
          });
      });

      it('throws when the client is not found', { timeout: 3000 }, () => {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(fixture8.provider).configuration, 'renderError');
        fixture8.provider.once('end_session_success.error', emitSpy);
        return fixture8.agent.get('/session/end/success?client_id=foobar')
          .set('Accept', 'text/html')
          .expect(400)
          .expect(() => {
            assert.equal(emitSpy.calledOnce, true);
            assert.equal(renderSpy.calledOnce, true);
            const renderArgs = renderSpy.args[0];
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client'); })(renderArgs[1]);
            ((actual) => { assert.ok(actual instanceof InvalidClient); })(renderArgs[2]);
          });
      });
    });
  });
});
