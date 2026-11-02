import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

function noW3A({ headers }) {
  assert.ok(!('www-authenticate' in Object(headers)));
}

describe('registration features', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('POST /reg', () => {
    const fixture1 = Object.create(fixture);

    it('rejects a JSON null Client Registration Request', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .set('Content-Type', 'application/json')
        .send('null')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client registration request must be a JSON object',
        }));

    it('generates the id, secret that does not expire and reg access token and returns the defaulted values', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect(201)
        .expect((response) => {
          assert.ok(['client_id', 'client_secret', 'registration_access_token'].every((key) => Object.keys(response.body).includes(key)));
          ((actual) => { assert.ok('client_secret_expires_at' in Object(actual)); assert.equal(actual.client_secret_expires_at, 0); })(response.body);
          ((actual) => { assert.ok('application_type' in Object(actual)); assert.equal(actual.application_type, 'web'); })(response.body);
          ((actual) => { assert.ok('id_token_signed_response_alg' in Object(actual)); assert.equal(actual.id_token_signed_response_alg, 'RS256'); })(response.body);
          ((actual) => { assert.ok('token_endpoint_auth_method' in Object(actual)); assert.equal(actual.token_endpoint_auth_method, 'client_secret_basic'); })(response.body);
          ((actual) => { assert.ok('require_auth_time' in Object(actual)); assert.equal(actual.require_auth_time, false); })(response.body);
          ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, ['authorization_code']); })(response.body);
          ((actual) => { assert.ok('response_types' in Object(actual)); assert.deepEqual(actual.response_types, ['code']); })(response.body);
          ((actual) => { assert.ok('registration_client_uri' in Object(actual)); assert.equal(actual.registration_client_uri, `${fixture1.provider.issuer}${fixture1.suitePath(`/reg/${response.body.client_id}`)}`); })(response.body);
        }));

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      fixture1.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'RegistrationAccessToken']));
      }, done);

      fixture1.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .end(() => {});
    });

    describe('when issueRegistrationAccessToken is false', () => {
      const fixture2 = Object.create(fixture1);

      before(() => {
        const config = i(fixture2.provider).features.registration;
        fixture2.orig = config.issueRegistrationAccessToken;
        config.issueRegistrationAccessToken = false;
      }, { timeout: 3000 });

      after(() => {
        i(fixture2.provider).features.registration.issueRegistrationAccessToken = fixture2.orig;
      }, { timeout: 3000 });

      it('omits issuing a registration access token and does not return registration_client_uri', { timeout: 3000 }, () => fixture2.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .expect(201)
          .expect((response) => {
            assert.ok(!(['registration_client_uri', 'registration_access_token'].every((key) => Object.keys(response.body).includes(key))));
          }));

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture2.assertOnce((ctx) => {
          assert.ok(!('RegistrationAccessToken' in Object(ctx.oidc.entities)));
        }, done);

        fixture2.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .end(() => {});
      });
    });

    describe('when issueRegistrationAccessToken is a function returning false', () => {
      const fixture3 = Object.create(fixture1);

      before(() => {
        const config = i(fixture3.provider).features.registration;
        fixture3.orig = config.issueRegistrationAccessToken;
        config.issueRegistrationAccessToken = () => false;
      }, { timeout: 3000 });

      after(() => {
        i(fixture3.provider).features.registration.issueRegistrationAccessToken = fixture3.orig;
      }, { timeout: 3000 });

      it('omits issuing a registration access token and does not return registration_client_uri', { timeout: 3000 }, () => fixture3.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .expect(201)
          .expect((response) => {
            assert.ok(!(['registration_client_uri', 'registration_access_token'].every((key) => Object.keys(response.body).includes(key))));
          }));

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture3.assertOnce((ctx) => {
          assert.ok(!('RegistrationAccessToken' in Object(ctx.oidc.entities)));
        }, done);

        fixture3.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .end(() => {});
      });
    });

    describe('when issueRegistrationAccessToken is an async function resolving false', () => {
      const fixture4 = Object.create(fixture1);

      before(() => {
        const config = i(fixture4.provider).features.registration;
        fixture4.orig = config.issueRegistrationAccessToken;
        config.issueRegistrationAccessToken = async () => false;
      }, { timeout: 3000 });

      after(() => {
        i(fixture4.provider).features.registration.issueRegistrationAccessToken = fixture4.orig;
      }, { timeout: 3000 });

      it('omits issuing a registration access token and does not return registration_client_uri', { timeout: 3000 }, () => fixture4.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .expect(201)
          .expect((response) => {
            assert.ok(!(['registration_client_uri', 'registration_access_token'].every((key) => Object.keys(response.body).includes(key))));
          }));

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture4.assertOnce((ctx) => {
          assert.ok(!('RegistrationAccessToken' in Object(ctx.oidc.entities)));
        }, done);

        fixture4.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .end(() => {});
      });
    });

    describe('when issueRegistrationAccessToken is a function returning true', () => {
      const fixture5 = Object.create(fixture1);

      before(() => {
        const config = i(fixture5.provider).features.registration;
        fixture5.orig = config.issueRegistrationAccessToken;
        config.issueRegistrationAccessToken = () => true;
      }, { timeout: 3000 });

      after(() => {
        i(fixture5.provider).features.registration.issueRegistrationAccessToken = fixture5.orig;
      }, { timeout: 3000 });

      it('issues a registration access token and does return registration_client_uri', { timeout: 3000 }, () => fixture5.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .expect(201)
          .expect((response) => {
            assert.ok(['registration_client_uri', 'registration_access_token'].every((key) => Object.keys(response.body).includes(key)));
          }));

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture5.assertOnce((ctx) => {
          assert.ok('RegistrationAccessToken' in Object(ctx.oidc.entities));
        }, done);

        fixture5.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .end(() => {});
      });
    });

    describe('when issueRegistrationAccessToken is true', () => {
      const fixture6 = Object.create(fixture1);

      before(() => {
        const config = i(fixture6.provider).features.registration;
        fixture6.orig = config.issueRegistrationAccessToken;
        config.issueRegistrationAccessToken = true;
      }, { timeout: 3000 });

      after(() => {
        i(fixture6.provider).features.registration.issueRegistrationAccessToken = fixture6.orig;
      }, { timeout: 3000 });

      it('issues a registration access token and does return registration_client_uri', { timeout: 3000 }, () => fixture6.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .expect(201)
          .expect((response) => {
            assert.ok(['registration_client_uri', 'registration_access_token'].every((key) => Object.keys(response.body).includes(key)));
          }));

      it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
        fixture6.assertOnce((ctx) => {
          assert.ok('RegistrationAccessToken' in Object(ctx.oidc.entities));
        }, done);

        fixture6.agent.post('/reg')
          .send({
            redirect_uris: ['https://client.example.com/cb'],
          })
          .end(() => {});
      });
    });

    it('omits the client_secret generation when it is not needed', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
        })
        .expect(201)
        .expect((response) => {
          assert.ok(!('client_secret' in Object(response.body)));
          assert.ok(!('client_secret_expires_at' in Object(response.body)));
        }));

    it('omits the client_secret generation when it is not needed and in doing so ignores provided client_secret and client_secret_expires_at', { timeout: 3000 }, async () => {
      const { body: { client_id } } = await fixture1.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
          client_secret: 'foo',
          client_secret_expires_at: 123,
        })
        .expect(201)
        .expect((response) => {
          assert.ok(!('client_secret' in Object(response.body)));
          assert.ok(!('client_secret_expires_at' in Object(response.body)));
        });

      const client = await fixture1.provider.Client.find(client_id);

      assert.ok(!('clientSecret' in Object(client)));
      assert.ok(!('clientSecretExpiresAt' in Object(client)));
    });

    it('issues the client_secret when needed for sig', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
          id_token_signed_response_alg: 'HS256',
        })
        .expect(201)
        .expect((response) => {
          assert.ok('client_secret' in Object(response.body));
          assert.ok('client_secret_expires_at' in Object(response.body));
        }));

    it('issues the client_secret when needed for auth', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'client_secret_jwt',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
        })
        .expect(201)
        .expect((response) => {
          assert.ok('client_secret' in Object(response.body));
          assert.ok('client_secret_expires_at' in Object(response.body));
        }));

    it('returns token-endpoint-like cache headers', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect('cache-control', 'no-store'));

    it('stores the client and emits an event', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.once('registration_create.success', spy);
      const adapter = fixture1.TestAdapter.for('Client');
      const upsert = sinon.spy(adapter, 'upsert');

      return fixture1.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect(() => {
          assert.equal(upsert.calledOnce, true);
          assert.equal(spy.calledOnce, true);
          assert.ok('oidc' in Object(spy.firstCall.args[0]));
          assert.equal(spy.firstCall.args[1].constructor.name, 'Client');
        });
    });

    it('uses the adapter to find stored clients', { timeout: 3000 }, () => {
      const adapter = fixture1.TestAdapter.for('Client');
      adapter.store.set('Client:foobar', {
        client_id: 'foobar',
        client_secret: 'foobarbaz',
        redirect_uris: ['https://client.example.com/cb'],
      });

      return fixture1.provider.Client.find('foobar')
        .then((client) => {
          assert.ok(client);
        });
    });

    it('validates the parameters to be valid and responds with errors', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
          grant_types: ['this is clearly wrong'],
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_client_metadata',
          error_description: "grant_types can only contain 'implicit', 'authorization_code', or 'refresh_token'",
        }));

    it('validates the parameters to be valid and responds with redirect_uri errors', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
        // redirect_uris missing here
        })
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_redirect_uri',
          error_description: 'redirect_uris is mandatory property',
        }));

    it('only accepts application/json POSTs', { timeout: 3000 }, () => fixture1.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'only application/json content-type bodies are supported on POST /reg',
        }));

    describe('initial access tokens', () => {
      const fixture7 = Object.create(fixture1);

      describe('fix string one', () => {
        const fixture8 = Object.create(fixture7);

        before(() => {
          fixture8.provider.enable('registration', { initialAccessToken: 'foobar' });
        }, { timeout: 3000 });

        after(() => {
          fixture8.provider.enable('registration', { initialAccessToken: undefined });
        }, { timeout: 3000 });

        it('fails reg calls with the access tokens in application/json body', { timeout: 3000 }, () => fixture8.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
              access_token: 'foobar',
            })
            .expect(fixture8.failWith(401, 'invalid_token', 'no access token provided')));

        it('allows reg calls with the access tokens as a Bearer token [header]', { timeout: 3000 }, () => fixture8.agent.post('/reg')
            .auth('foobar', { type: 'bearer' })
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .expect(201));

        it('rejects calls with bad access token', { timeout: 3000 }, () => fixture8.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth('foobarbaz', { type: 'bearer' })
            .expect(fixture8.failWith(401, 'invalid_token', 'invalid token provided')));
      });

      describe('using a model', () => {
        const fixture9 = Object.create(fixture7);

        before(() => {
          fixture9.provider.enable('registration', { initialAccessToken: true });

          const iat = new (fixture9.provider.InitialAccessToken)({});
          return iat.save().then((value) => {
            fixture9.token = value;
          });
        }, { timeout: 3000 });

        after(() => {
          fixture9.provider.enable('registration', { initialAccessToken: undefined });
        }, { timeout: 3000 });

        it('allows the developers to insert new tokens with no expiration', { timeout: 3000 }, () => new fixture9.provider.InitialAccessToken().save().then((v) => {
            const jti = fixture9.getTokenJti(v);
            const token = fixture9.TestAdapter.for('InitialAccessToken').syncFind(jti);
            assert.ok(!('exp' in Object(token)));
          }));

        it('allows the developers to insert new tokens with expiration', { timeout: 3000 }, () => new fixture9.provider.InitialAccessToken({
            expiresIn: 24 * 60 * 60,
          }).save().then((v) => {
            const jti = fixture9.getTokenJti(v);
            const token = fixture9.TestAdapter.for('InitialAccessToken').syncFind(jti);
            assert.ok('exp' in Object(token));
          }));

        it('fails reg calls with the access tokens in application/json body', { timeout: 3000 }, () => fixture9.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
              access_token: fixture9.token,
            })
            .expect(fixture9.failWith(401, 'invalid_token', 'no access token provided')));

        it('allows reg calls with the access tokens as a Bearer token [header]', { timeout: 3000 }, () => fixture9.agent.post('/reg')
            .auth(fixture9.token, { type: 'bearer' })
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .expect(201));

        it('adds InitialAccessToken to ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
          fixture9.assertOnce((ctx) => {
            assert.ok('InitialAccessToken' in Object(ctx.oidc.entities));
          }, done);

          fixture9.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth(fixture9.token, { type: 'bearer' })
            .end(() => {});
        });

        it('rejects calls with bad access token', { timeout: 3000 }, () => fixture9.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth('foobarbaz', { type: 'bearer' })
            .expect(fixture9.failWith(401, 'invalid_token', 'invalid token provided')));

        it('rejects calls with not found access token', { timeout: 3000 }, () => fixture9.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth('Loremipsumdolorsitametconsecteturadipisicingelitsed', { type: 'bearer' })
            .expect(fixture9.failWith(401, 'invalid_token', 'invalid token provided')));

        it('rejects calls with manipulated access token', { timeout: 3000 }, () => fixture9.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth(fixture9.token.slice(0, -1), { type: 'bearer' })
            .expect(fixture9.failWith(401, 'invalid_token', 'invalid token provided')));
      });
    });
  });

  describe('GET /reg/:clientId', () => {
    const fixture10 = Object.create(fixture);

    before(() => fixture10.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect((response) => {
          fixture10.clientId = response.body.client_id;
          fixture10.token = response.body.registration_access_token;
          fixture10.registrationResponse = response.body;
        }), { timeout: 3000 });

    it('returns all available nonsecret metadata', { timeout: 3000 }, () => fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .auth(fixture10.token, { type: 'bearer' })
        .expect(200)
        .expect('content-type', /application\/json/)
        .expect((response) => {
          assert.ok(['client_id', 'client_secret', 'registration_access_token'].every((key) => Object.keys(response.body).includes(key)));
          ((actual) => { assert.ok('client_secret_expires_at' in Object(actual)); assert.equal(actual.client_secret_expires_at, 0); })(response.body);
          ((actual) => { assert.ok('application_type' in Object(actual)); assert.equal(actual.application_type, 'web'); })(response.body);
          ((actual) => { assert.ok('id_token_signed_response_alg' in Object(actual)); assert.equal(actual.id_token_signed_response_alg, 'RS256'); })(response.body);
          ((actual) => { assert.ok('token_endpoint_auth_method' in Object(actual)); assert.equal(actual.token_endpoint_auth_method, 'client_secret_basic'); })(response.body);
          ((actual) => { assert.ok('require_auth_time' in Object(actual)); assert.equal(actual.require_auth_time, false); })(response.body);
          ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, ['authorization_code']); })(response.body);
          ((actual) => { assert.ok('response_types' in Object(actual)); assert.deepEqual(actual.response_types, ['code']); })(response.body);
          ((actual) => { assert.ok('registration_client_uri' in Object(actual)); assert.equal(actual.registration_client_uri, `${fixture10.provider.issuer}${fixture10.suitePath(`/reg/${response.body.client_id}`)}`); })(response.body);
        }));

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      fixture10.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'RegistrationAccessToken']));
      }, done);

      fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .auth(fixture10.token, { type: 'bearer' })
        .end(() => {});
    });

    it('returns token-endpoint-like cache headers', { timeout: 3000 }, () => fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .auth(fixture10.token, { type: 'bearer' })
        .expect('cache-control', 'no-store'));

    it('validates client is a valid client', { timeout: 3000 }, () => fixture10.agent.get('/reg/thisDOesnotCompute')
        .auth('wahtever', { type: 'bearer' })
        .expect(fixture10.failWith(401, 'invalid_token', 'invalid token provided')));

    it('validates auth presence', { timeout: 3000 }, () => fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .expect(fixture10.failWith(401, 'invalid_token', 'no access token provided')));

    it('validates auth', { timeout: 3000 }, () => fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .auth('invalidtoken', { type: 'bearer' })
        .expect(fixture10.failWith(401, 'invalid_token', 'invalid token provided')));

    it('validates auth (notfoundtoken)', { timeout: 3000 }, () => fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .auth('Loremipsumdolorsitametconsecteturadipisicingelitsed', { type: 'bearer' })
        .expect(fixture10.failWith(401, 'invalid_token', 'invalid token provided')));

    it('accepts query', { timeout: 3000 }, () => fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .auth(fixture10.token, { type: 'bearer' })
        .expect(200));

    it('accepts header', { timeout: 3000 }, () => fixture10.agent.get(`/reg/${fixture10.clientId}`)
        .auth(fixture10.token, { type: 'bearer' })
        .expect(200));

    it('invalidates registration_access_token if used on the wrong client', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture10.provider.once('registration_access_token.destroyed', spy);

      return fixture10.agent.get('/reg/foobar')
        .auth(fixture10.token, { type: 'bearer' })
        .expect('cache-control', 'no-store')
        .expect(fixture10.failWith(401, 'invalid_token', 'invalid token provided'))
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(spy.firstCall.args[0].constructor.name, 'RegistrationAccessToken');
          assert.equal(spy.firstCall.args[0].clientId, fixture10.clientId);
        });
    });

    it('cannot read non-dynamic clients', { timeout: 3000 }, async () => {
      const rat = new (fixture10.provider.RegistrationAccessToken)({ clientId: 'client' });
      const bearer = await rat.save();
      return fixture10.agent.get('/reg/client')
        .auth(bearer, { type: 'bearer' })
        .expect(403)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client does not have permission to read its record',
        });
    });
  });
});
