import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

const route = '/token/introspection';

describe('introspection features', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('enriched discovery', () => {
    const fixture1 = Object.create(fixture);

    it('shows the url now', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('introspection_endpoint' in Object(actual)); assert.match(actual.introspection_endpoint, /token\/introspect/); })(response.body);
          assert.ok(!('introspection_signing_alg_values_supported' in Object(response.body)));
        }));
  });

  describe('/token/introspection', () => {
    const fixture2 = Object.create(fixture);

    before(() => fixture2.login({ accountId: 'accountId' }), { timeout: 3000 });
    it('returns the properties for access token [no hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
        aud: 'urn:example:foo',
      });

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub', 'iss', 'iat', 'exp', 'token_type', 'aud'].every((key) => Object.keys(response.body).includes(key)));
          assert.equal(response.body.sub, 'accountId');
          assert.equal(response.body.token_type, 'Bearer');
          assert.equal(response.body.iss, fixture2.provider.issuer);
          assert.equal(response.body.aud, 'urn:example:foo');
        });
    });

    it('returns the properties for access token [correct hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'access_token',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
          assert.equal(response.body.sub, 'accountId');
        });
    });

    it('returns the properties for access token [wrong hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
          assert.equal(response.body.sub, 'accountId');
        });
    });

    it('returns the properties for access token [unrecognized hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'foobar',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
          assert.equal(response.body.sub, 'accountId');
        });
    });

    it('returns the properties for refresh token [no hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
        });
    });

    it('returns the properties for refresh token [correct hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
        });
    });

    it('returns the properties for refresh token [wrong hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
        });
    });

    it('returns the properties for refresh token [unrecognized hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
        });
    });

    it('returns the properties for client credentials token [no hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.ClientCredentials({
        client: await fixture2.provider.Client.find('client'),
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id'].every((key) => Object.keys(response.body).includes(key)));
        });
    });

    it('returns the properties for client credentials token [correct hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.ClientCredentials({
        client: await fixture2.provider.Client.find('client'),
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id'].every((key) => Object.keys(response.body).includes(key)));
        });
    });

    it('returns the properties for client credentials token [unrecognized hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.ClientCredentials({
        client: await fixture2.provider.Client.find('client'),
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id'].every((key) => Object.keys(response.body).includes(key)));
        });
    });

    it('rejects structured tokens', { timeout: 3000 }, () => fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
        })
        .type('form')
        .expect(400)
        .expect({ error: 'unsupported_token_type', error_description: 'Structured JWT Tokens cannot be introspected via the introspection_endpoint' }));

    it('can be called by pairwise clients', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId('client-pairwise'),
        clientId: 'client-pairwise',
        scope: 'scope',
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client-pairwise', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
          assert.notEqual(response.body.sub, 'accountId');
        });
    });

    it('can be called by RS clients and uses the original subject_type', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId('client-pairwise'),
        clientId: 'client-pairwise',
        scope: 'scope',
      });

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client-introspection', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          assert.ok(['client_id', 'scope', 'sub'].every((key) => Object.keys(response.body).includes(key)));
          assert.notEqual(response.body.sub, 'accountId');
        });
    });

    it('returns token-endpoint-like cache headers', { timeout: 3000 }, () => fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({})
        .type('form')
        .expect('cache-control', 'no-store'));

    it('validates token param presence', { timeout: 3000 }, () => fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({})
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "missing required parameter 'token'"); })(response.body);
        }));

    it('responds with active=false for total bs', { timeout: 3000 }, () => fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'this is not even a token',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, false); })(response.body);
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['active']));
        }));

    it('responds with active=false when client auth = none and token does not belong to it', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return fixture2.agent.post(route)
        .send({
          token,
          client_id: 'client-none',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, false); })(response.body);
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['active']));
        });
    });

    it('emits on (i.e. auth) error', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture2.provider.once('introspection.error', spy);

      return fixture2.agent.post(route)
        .auth('client', 'invalid')
        .send({})
        .type('form')
        .expect(401)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        });
    });

    it('ignores unsupported tokens', { timeout: 3000 }, async () => {
      const ac = new fixture2.provider.AuthorizationCode({ clientId: 'client' });
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: await ac.save(),
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, false); })(response.body);
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['active']));
        });
    });

    it('responds only with active=false when token is expired', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
        expiresIn: -1,
      });

      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: await at.save(),
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, false); })(response.body);
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['active']));
        });
    });

    it('responds only with active=false when token is already consumed', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      await rt.consume();

      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, false); })(response.body);
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['active']));
        });
    });

    it('does not allow to introspect the uninstrospectable (in case adapter is implemented wrong)', { timeout: 3000 }, async () => {
      sinon.stub(fixture2.provider.AccessToken, 'find').callsFake(() => ({
        isValid: true,
        kind: 'AuthorizationCode',
      }));

      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'foo',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, false); })(response.body);
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['active']));
          fixture2.provider.AccessToken.find.restore();
        })
        .catch((err) => {
          fixture2.provider.AccessToken.find.restore();
          throw err;
        });
    });

    describe('populates ctx.oidc.entities', () => {
      const fixture3 = Object.create(fixture2);

      it('when introspecting an AccessToken', { timeout: 3000 }, (_t, done) => {
        fixture3.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'AccessToken']));
        }, done);

        (async () => {
          const at = new fixture3.provider.AccessToken({
            accountId: 'accountId',
            client: await fixture3.provider.Client.find('client'),
            scope: 'scope',
          });

          const token = await at.save();
          await fixture3.agent.post(route)
            .auth('client', 'secret')
            .send({
              token,
            })
            .type('form');
        })().catch(done);
      });

      it('when introspecting a RefreshToken', { timeout: 3000 }, (_t, done) => {
        fixture3.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'RefreshToken']));
        }, done);

        (async () => {
          const rt = new fixture3.provider.RefreshToken({
            accountId: 'accountId',
            client: await fixture3.provider.Client.find('client'),
            scope: 'scope',
          });

          const token = await rt.save();
          await fixture3.agent.post(route)
            .auth('client', 'secret')
            .send({ token })
            .type('form');
        })().catch(done);
      });

      it('when introspecting ClientCredentials', { timeout: 3000 }, (_t, done) => {
        fixture3.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'ClientCredentials']));
        }, done);

        (async () => {
          const rt = new fixture3.provider.ClientCredentials({
            client: await fixture3.provider.Client.find('client'),
          });

          const token = await rt.save();
          await fixture3.agent.post(route)
            .auth('client', 'secret')
            .send({ token })
            .type('form');
        })().catch(done);
      });
    });
  });
});
