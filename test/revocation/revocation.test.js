import { createSandbox } from 'sinon';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

const sinon = createSandbox();
const route = '/token/revocation';

describe('revocation features', () => {
  before(bootstrap(import.meta.url));
  afterEach(sinon.restore);

  describe('enriched discovery', () => {
    it('shows the url now', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('revocation_endpoint').and.matches(/token\/revocation/);
          expect(response.body).not.to.have.property('token_revocation_endpoint');
        });
    });
  });

  describe(route, () => {
    it('revokes access token [no hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const atDestroy = sinon.stub(this.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());
      const grantDestroy = sinon.stub(this.provider.Grant.adapter, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(atDestroy.calledOnce).to.be.true;
          expect(grantDestroy.called).to.be.false;
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token and grant when configured', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      sinon.stub(i(this.provider).configuration, 'revokeGrantPolicy').callsFake(() => true);
      const atDestroy = sinon.stub(this.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());
      const grantDestroy = sinon.stub(this.provider.Grant.adapter, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(atDestroy.calledOnce).to.be.true;
          expect(grantDestroy.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [correct hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [wrong hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [unrecognized hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('propagates exceptions on find', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      sinon.stub(this.provider.AccessToken, 'find').callsFake(async () => { throw new Error(); });

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(500)
        .expect((response) => {
          expect(response.body.error).to.eql('server_error');
        });
    });

    it('revokes refresh token [no hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const rtDestroy = sinon.stub(this.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());
      const grantDestroy = sinon.stub(this.provider.Grant.adapter, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(rtDestroy.calledOnce).to.be.true;
          expect(grantDestroy.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [correct hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'refresh_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [wrong hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [unrecognized hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [no hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        client: await this.provider.Client.find('client'),
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [correct hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        client: await this.provider.Client.find('client'),
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [unrecognized hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        client: await this.provider.Client.find('client'),
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
        })
        .expect(200)
        .expect('');
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

    it('rejects completely wrong tokens with the expected OK response', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'dsahjdasdsa',
        })
        .type('form')
        .expect('')
        .expect(200);
    });

    it('rejects structured tokens', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
        })
        .type('form')
        .expect(400)
        .expect({ error: 'unsupported_token_type', error_description: 'Structured JWT Tokens cannot be revoked via the revocation_endpoint' });
    });

    it('does not revoke tokens of other clients (confidential client making the request - exposed error)', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client2'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy');

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client is not authorized to revoke the presented token',
        })
        .expect(() => {
          expect(stub.called).to.be.false;
        });
    });

    it('does not revoke tokens of other clients (public client making the request - silent ignore)', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        client: await this.provider.Client.find('client2'),
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy');

      const token = await at.save();
      return this.agent.post(route)
        .send({ token, client_id: 'client-public' })
        .type('form')
        .expect(200)
        .expect('')
        .expect(() => {
          expect(stub.called).to.be.false;
        });
    });

    it('emits on (i.e. auth) error', function () {
      const spy = sinon.spy();
      this.provider.once('revocation.error', spy);

      return this.agent.post(route)
        .auth('client', 'invalid')
        .send({})
        .type('form')
        .expect(401)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        });
    });

    it('does not allow to revoke the unrevokable (in case adapter is implemented wrong)', async function () {
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
        .catch((err) => {
          throw err;
        });
    });

    describe('populates ctx.oidc.entities', () => {
      it('when revoking an AccessToken', function (done) {
        this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'AccessToken');
        }, done);

        (async () => {
          const at = new this.provider.AccessToken({
            accountId: 'accountId',
            grantId: 'foo',
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

      it('when revoking a RefreshToken', function (done) {
        this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'RefreshToken');
        }, done);

        (async () => {
          const rt = new this.provider.RefreshToken({
            accountId: 'accountId',
            grantId: 'foo',
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

      it('when revoking ClientCredentials', function (done) {
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
