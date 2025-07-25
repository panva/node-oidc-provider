import sinon from 'sinon';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

const route = '/token/introspection';

describe('introspection features', () => {
  before(bootstrap(import.meta.url));

  describe('enriched discovery', () => {
    it('shows the url now', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('introspection_endpoint').and.matches(/token\/introspect/);
          expect(response.body).not.to.have.property('introspection_signing_alg_values_supported');
        });
    });
  });

  describe('/token/introspection', () => {
    before(function () { return this.login({ accountId: 'accountId' }); });
    it('returns the properties for access token [no hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
        aud: 'urn:example:foo',
      });

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub', 'iss', 'iat', 'exp', 'token_type', 'aud');
          expect(response.body.sub).to.equal('accountId');
          expect(response.body.token_type).to.equal('Bearer');
          expect(response.body.iss).to.equal(this.provider.issuer);
          expect(response.body.aud).to.equal('urn:example:foo');
        });
    });

    it('returns the properties for access token [correct hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'access_token',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).to.equal('accountId');
        });
    });

    it('returns the properties for access token [wrong hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).to.equal('accountId');
        });
    });

    it('returns the properties for access token [unrecognized hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
          token_type_hint: 'foobar',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).to.equal('accountId');
        });
    });

    it('returns the properties for refresh token [no hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        });
    });

    it('returns the properties for refresh token [correct hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        });
    });

    it('returns the properties for refresh token [wrong hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        });
    });

    it('returns the properties for refresh token [unrecognized hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
        });
    });

    it('returns the properties for client credentials token [no hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        client: await this.provider.Client.find('client'),
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id');
        });
    });

    it('returns the properties for client credentials token [correct hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        client: await this.provider.Client.find('client'),
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id');
        });
    });

    it('returns the properties for client credentials token [unrecognized hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        client: await this.provider.Client.find('client'),
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id');
        });
    });

    it('rejects structured tokens', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
        })
        .type('form')
        .expect(400)
        .expect({ error: 'unsupported_token_type', error_description: 'Structured JWT Tokens cannot be introspected via the introspection_endpoint' });
    });

    it('can be called by pairwise clients', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: this.getGrantId('client-pairwise'),
        clientId: 'client-pairwise',
        scope: 'scope',
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client-pairwise', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).not.to.equal('accountId');
        });
    });

    it('can be called by RS clients and uses the original subject_type', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: this.getGrantId('client-pairwise'),
        clientId: 'client-pairwise',
        scope: 'scope',
      });

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client-introspection', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'scope', 'sub');
          expect(response.body.sub).not.to.equal('accountId');
        });
    });

    it('returns token-endpoint-like cache headers', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({})
        .type('form')
        .expect('cache-control', 'no-store');
    });

    it('validates token param presence', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({})
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_request');
          expect(response.body).to.have.property('error_description', "missing required parameter 'token'");
        });
    });

    it('responds with active=false for total bs', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'this is not even a token',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('active', false);
          expect(response.body).to.have.keys('active');
        });
    });

    it('responds with active=false when client auth = none and token does not belong to it', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await at.save();
      return this.agent.post(route)
        .send({
          token,
          client_id: 'client-none',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('active', false);
          expect(response.body).to.have.keys('active');
        });
    });

    it('emits on (i.e. auth) error', function () {
      const spy = sinon.spy();
      this.provider.once('introspection.error', spy);

      return this.agent.post(route)
        .auth('client', 'invalid')
        .send({})
        .type('form')
        .expect(401)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        });
    });

    it('ignores unsupported tokens', async function () {
      const ac = new this.provider.AuthorizationCode({ clientId: 'client' });
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: await ac.save(),
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('active', false);
          expect(response.body).to.have.keys('active');
        });
    });

    it('responds only with active=false when token is expired', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
        expiresIn: -1,
      });

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: await at.save(),
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('active', false);
          expect(response.body).to.have.keys('active');
        });
    });

    it('responds only with active=false when token is already consumed', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const token = await rt.save();
      await rt.consume();

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token,
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('active', false);
          expect(response.body).to.have.keys('active');
        });
    });

    it('does not allow to introspect the uninstrospectable (in case adapter is implemented wrong)', async function () {
      sinon.stub(this.provider.AccessToken, 'find').callsFake(() => ({
        isValid: true,
        kind: 'AuthorizationCode',
      }));

      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'foo',
        })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('active', false);
          expect(response.body).to.have.keys('active');
          this.provider.AccessToken.find.restore();
        })
        .catch((err) => {
          this.provider.AccessToken.find.restore();
          throw err;
        });
    });

    describe('populates ctx.oidc.entities', () => {
      it('when introspecting an AccessToken', function (done) {
        this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'AccessToken');
        }, done);

        (async () => {
          const at = new this.provider.AccessToken({
            accountId: 'accountId',
            client: await this.provider.Client.find('client'),
            scope: 'scope',
          });

          const token = await at.save();
          await this.agent.post(route)
            .auth('client', 'secret')
            .send({
              token,
            })
            .type('form');
        })().catch(done);
      });

      it('when introspecting a RefreshToken', function (done) {
        this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'RefreshToken');
        }, done);

        (async () => {
          const rt = new this.provider.RefreshToken({
            accountId: 'accountId',
            client: await this.provider.Client.find('client'),
            scope: 'scope',
          });

          const token = await rt.save();
          await this.agent.post(route)
            .auth('client', 'secret')
            .send({ token })
            .type('form');
        })().catch(done);
      });

      it('when introspecting ClientCredentials', function (done) {
        this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'ClientCredentials');
        }, done);

        (async () => {
          const rt = new this.provider.ClientCredentials({
            client: await this.provider.Client.find('client'),
          });

          const token = await rt.save();
          await this.agent.post(route)
            .auth('client', 'secret')
            .send({ token })
            .type('form');
        })().catch(done);
      });
    });
  });
});
