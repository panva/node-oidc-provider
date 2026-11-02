import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import omit from 'lodash/omit.js';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';
import Provider from '../../lib/index.js';

function noW3A({ headers }) {
  assert.ok(!('www-authenticate' in Object(headers)));
}

describe('OAuth 2.0 Dynamic Client Registration Management Protocol', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  // setup does not have the provider;

  function setup(metadata) {
    const props = { redirect_uris: ['https://client.example.com/cb'], ...metadata };

    return this.agent.post('/reg').send(props).expect(201)
      .then((res) => res.body);
  }

  describe('feature flag', () => {
    it('checks registration is also enabled', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Provider('http://localhost', {
          features: {
            registrationManagement: { enabled: true },
          },
        });
      }, (error) => { assert.ok(error.message.includes('registrationManagement is only available in conjunction with registration')); return true; });
    });
  });

  describe('Client Update Request', () => {
    const fixture2 = Object.create(fixture);

    const NOGO = ['registration_access_token', 'registration_client_uri', 'client_secret_expires_at', 'client_id_issued_at'];
    function updateProperties(client, props) {
      return Object.assign(omit(client, NOGO), props);
    }

    it('responds w/ 200 JSON and nocache headers', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
        }))
        .expect(200)
        .expect('content-type', /application\/json/)
        .expect('cache-control', 'no-store')
        .expect((res) => {
          ((actual) => { assert.ok('registration_access_token' in Object(actual)); assert.equal(actual.registration_access_token, client.registration_access_token); })(res.body);
          ((actual) => { assert.ok('registration_client_uri' in Object(actual)); assert.equal(actual.registration_client_uri, client.registration_client_uri); })(res.body);
          ((actual) => { assert.ok('client_secret_expires_at' in Object(actual)); assert.equal(actual.client_secret_expires_at, client.client_secret_expires_at); })(res.body);
          ((actual) => { assert.ok('client_id_issued_at' in Object(actual)); assert.equal(actual.client_id_issued_at, client.client_id_issued_at); })(res.body);
          assert.deepEqual(res.body.redirect_uris, ['https://client.example.com/foobar/cb']);
        });
    });

    it('rejects calls with bad registration access token', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth('foobarbaz', { type: 'bearer' })
        .expect(fixture2.failWith(401, 'invalid_token', 'invalid token provided'));
    });

    it('rejects calls with no registration access token', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .expect(fixture2.failWith(401, 'invalid_token', 'no access token provided'));
    });

    it('rejects a JSON null Client Update Request', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});

      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .set('Content-Type', 'application/json')
        .send('null')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client update request must be a JSON object',
        });
    });

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      (async () => {
        const client = await setup.call(fixture2, {});
        fixture2.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'RegistrationAccessToken']));
        }, done);
        await fixture2.agent.put(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' })
          .send(updateProperties(client));
      })().catch(done);
    });

    it('allows for properties to be deleted', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, { userinfo_signed_response_alg: 'RS256' });
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          userinfo_signed_response_alg: null,
        }))
        .expect(200)
        .expect((res) => {
          assert.ok(!('userinfo_signed_response_alg' in Object(res.body)));
        });
    });

    it('allows for properties to be deleted (not client_secret tho)', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          client_secret: null,
        }))
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: "provided client_secret does not match the authenticated client's one",
        });
    });

    it('allows for properties to be deleted by omission', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, { userinfo_signed_response_alg: 'RS256' });
      delete client.userinfo_signed_response_alg;
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client))
        .expect(200)
        .expect((res) => {
          assert.ok(!('userinfo_signed_response_alg' in Object(res.body)));
        });
    });

    it('provides a secret if suddently needed', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, { token_endpoint_auth_method: 'none', response_types: ['id_token'], grant_types: ['implicit'] });
      assert.ok(!('client_secret' in Object(client)));
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          response_types: ['code'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'client_secret_basic',
        }))
        .expect(200)
        .expect((res) => {
          assert.ok('client_secret' in Object(res.body));
          assert.ok('client_secret_expires_at' in Object(res.body));
        });
    });

    it('emits an event', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      const spy = sinon.spy();
      fixture2.provider.once('registration_update.success', spy);

      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client))
        .expect(200)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        });
    });

    it('must not contain registration_access_token', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      // changing the redirect_uris;
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          registration_access_token: 'foobar',
        }))
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'request MUST NOT include the registration_access_token field',
        });
    });

    it('must not contain registration_client_uri', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      // changing the redirect_uris;
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          registration_client_uri: 'foobar',
        }))
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'request MUST NOT include the registration_client_uri field',
        });
    });

    it('must not contain client_secret_expires_at', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      // changing the redirect_uris;
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          client_secret_expires_at: 'foobar',
        }))
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'request MUST NOT include the client_secret_expires_at field',
        });
    });

    it('must not contain client_id_issued_at', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture2, {});
      // changing the redirect_uris;
      return fixture2.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          client_id_issued_at: 'foobar',
        }))
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'request MUST NOT include the client_id_issued_at field',
        });
    });

    it('cannot update non-dynamic clients', { timeout: 3000 }, async () => {
      const rat = new (fixture2.provider.RegistrationAccessToken)({ clientId: 'client' });
      const bearer = await rat.save();
      const client = await fixture2.provider.Client.find('client');
      return fixture2.agent.put('/reg/client')
        .auth(bearer, { type: 'bearer' })
        .send(updateProperties(client.metadata(), {
          redirect_uris: ['https://client.example.com/foobar/cb'],
        }))
        .expect(403)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client does not have permission to update its record',
        });
    });

    describe('rotateRegistrationAccessToken', () => {
      const fixture3 = Object.create(fixture2);

      before(() => {
        const conf = i(fixture3.provider).configuration;
        conf.features.registrationManagement = {
          enabled: true, rotateRegistrationAccessToken: true,
        };
      }, { timeout: 3000 });

      after(() => {
        const conf = i(fixture3.provider).configuration;
        conf.features.registrationManagement = { enabled: true };
      }, { timeout: 3000 });

      it('destroys the old RegistrationAccessToken', { timeout: 3000 }, async () => {
        const client = await setup.call(fixture3, {});
        const spy = sinon.spy();
        fixture3.provider.once('registration_access_token.destroyed', spy);

        return fixture3.agent.put(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' })
          .send(updateProperties(client))
          .expect(200)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          });
      });

      it('populates ctx.oidc.entities with RotatedRegistrationAccessToken too', { timeout: 3000 }, (_t, done) => {
        (async () => {
          const client = await setup.call(fixture3, {});
          fixture3.assertOnce((ctx) => {
            assert.ok(['RotatedRegistrationAccessToken', 'RegistrationAccessToken'].every((key) => Object.keys(ctx.oidc.entities).includes(key)));
            assert.notDeepEqual(ctx.oidc.entities.RotatedRegistrationAccessToken, ctx.oidc.entities.RegistrationAccessToken);
          }, done);
          await fixture3.agent.put(`/reg/${client.client_id}`)
            .auth(client.registration_access_token, { type: 'bearer' })
            .send(updateProperties(client));
        })().catch(done);
      });

      it('issues and returns new RegistrationAccessToken', { timeout: 3000 }, async () => {
        const client = await setup.call(fixture3, {});
        const spy = sinon.spy();
        fixture3.provider.once('registration_access_token.saved', spy);

        return fixture3.agent.put(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' })
          .send(updateProperties(client))
          .expect(200)
          .expect((response) => {
            assert.equal(spy.calledOnce, true);
            const args = spy.firstCall.args[0];
            assert.equal(args.clientId, client.client_id);
            assert.equal(fixture3.getTokenJti(response.body.registration_access_token), args.jti);
          });
      });
    });
  });

  describe('Client Delete Request', () => {
    const fixture4 = Object.create(fixture);

    it('responds w/ empty 204 and nocache headers and removes the registration access token', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture4, {});
      await fixture4.agent.del(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .expect('cache-control', 'no-store')
        .expect('') // empty body
        .expect(204);

      assert.equal(await fixture4.provider.RegistrationAccessToken.find(client.registration_access_token), undefined);
    });

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      (async () => {
        const client = await setup.call(fixture4, {});
        fixture4.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'RegistrationAccessToken']));
        }, done);
        await fixture4.agent.del(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' });
      })().catch(done);
    });

    it('emits an event', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture4, {});
      const spy = sinon.spy();
      fixture4.provider.once('registration_delete.success', spy);

      return fixture4.agent.del(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .expect(204)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        });
    });

    it('rejects calls with bad registration access token', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture4, {});
      return fixture4.agent.del(`/reg/${client.client_id}`)
        .auth('foobarbaz', { type: 'bearer' })
        .expect(fixture4.failWith(401, 'invalid_token', 'invalid token provided'));
    });

    it('rejects calls with no registration access token', { timeout: 3000 }, async () => {
      const client = await setup.call(fixture4, {});
      return fixture4.agent.del(`/reg/${client.client_id}`)
        .expect(fixture4.failWith(401, 'invalid_token', 'no access token provided'));
    });

    it('cannot delete non-dynamic clients', { timeout: 3000 }, async () => {
      const rat = new (fixture4.provider.RegistrationAccessToken)({ clientId: 'client' });
      const bearer = await rat.save();
      return fixture4.agent.del('/reg/client')
        .auth(bearer, { type: 'bearer' })
        .expect(403)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client does not have permission to delete its record',
        });
    });
  });
});
