import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';

import bootstrap from '../test_helper.js';

const sinon = createSandbox();
const route = '/token/revocation';

describe('revocation features', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  describe('enriched discovery', () => {
    const fixture1 = Object.create(fixture);

    it('shows the url now', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('revocation_endpoint' in Object(actual)); assert.match(actual.revocation_endpoint, /token\/revocation/); })(response.body);
          assert.ok(!('token_revocation_endpoint' in Object(response.body)));
        }));
  });

  describe(route, () => {
    const fixture2 = Object.create(fixture);

    it('revokes access token [no hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const atDestroy = sinon.stub(fixture2.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());
      const grantDestroy = sinon.stub(fixture2.provider.Grant.adapter, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          assert.equal(atDestroy.calledOnce, true);
          assert.equal(grantDestroy.called, false);
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token and grant when configured', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      sinon.stub(i(fixture2.provider).configuration, 'revokeGrantPolicy').callsFake(() => true);
      const atDestroy = sinon.stub(fixture2.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());
      const grantDestroy = sinon.stub(fixture2.provider.Grant.adapter, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          assert.equal(atDestroy.calledOnce, true);
          assert.equal(grantDestroy.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [correct hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [wrong hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [unrecognized hint]', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('propagates exceptions on find', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      sinon.stub(fixture2.provider.AccessToken, 'find').callsFake(async () => { throw new Error(); });

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(500)
        .expect((response) => {
          assert.deepEqual(response.body.error, 'server_error');
        });
    });

    it('revokes refresh token [no hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const rtDestroy = sinon.stub(fixture2.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());
      const grantDestroy = sinon.stub(fixture2.provider.Grant.adapter, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          assert.equal(rtDestroy.calledOnce, true);
          assert.equal(grantDestroy.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [correct hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [wrong hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [unrecognized hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [no hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.ClientCredentials({
        client: await fixture2.provider.Client.find('client'),
      });

      const stub = sinon.stub(fixture2.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [correct hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.ClientCredentials({
        client: await fixture2.provider.Client.find('client'),
      });

      const stub = sinon.stub(fixture2.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [unrecognized hint]', { timeout: 3000 }, async () => {
      const rt = new fixture2.provider.ClientCredentials({
        client: await fixture2.provider.Client.find('client'),
      });

      const stub = sinon.stub(fixture2.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          assert.equal(stub.calledOnce, true);
        })
        .expect(200)
        .expect('');
    });

    it('validates token param presence', { timeout: 3000 }, () => fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({})
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "missing required parameter 'token'"); })(response.body);
        }));

    it('rejects completely wrong tokens with the expected OK response', { timeout: 3000 }, () => fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'dsahjdasdsa',
        })
        .type('form')
        .expect('')
        .expect(200));

    it('rejects structured tokens', { timeout: 3000 }, () => fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
        })
        .type('form')
        .expect(400)
        .expect({ error: 'unsupported_token_type', error_description: 'Structured JWT Tokens cannot be revoked via the revocation_endpoint' }));

    it('does not revoke tokens of other clients (confidential client making the request - exposed error)', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client2'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.AccessToken.prototype, 'destroy');

      const token = await at.save();
      return fixture2.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client is not authorized to revoke the presented token',
        })
        .expect(() => {
          assert.equal(stub.called, false);
        });
    });

    it('does not revoke tokens of other clients (public client making the request - silent ignore)', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await fixture2.provider.Client.find('client2'),
        scope: 'scope',
      });

      const stub = sinon.stub(fixture2.provider.AccessToken.prototype, 'destroy');

      const token = await at.save();
      return fixture2.agent.post(route)
        .send({ token, client_id: 'client-public' })
        .type('form')
        .expect(200)
        .expect('')
        .expect(() => {
          assert.equal(stub.called, false);
        });
    });

    it('emits on (i.e. auth) error', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture2.provider.once('revocation.error', spy);

      return fixture2.agent.post(route)
        .auth('client', 'invalid')
        .send({})
        .type('form')
        .expect(401)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        });
    });

    it('does not allow to revoke the unrevokable (in case adapter is implemented wrong)', { timeout: 3000 }, async () => {
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
        .catch((err) => {
          throw err;
        });
    });

    describe('populates ctx.oidc.entities', () => {
      const fixture3 = Object.create(fixture2);

      it('when revoking an AccessToken', { timeout: 3000 }, (_t, done) => {
        fixture3.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'AccessToken']));
        }, done);

        (async () => {
          const at = new fixture3.provider.AccessToken({
            accountId: 'accountId',
            grantId: 'foo',
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

      it('when revoking a RefreshToken', { timeout: 3000 }, (_t, done) => {
        fixture3.assertOnce((ctx) => {
          assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'RefreshToken']));
        }, done);

        (async () => {
          const rt = new fixture3.provider.RefreshToken({
            accountId: 'accountId',
            grantId: 'foo',
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

      it('when revoking ClientCredentials', { timeout: 3000 }, (_t, done) => {
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
