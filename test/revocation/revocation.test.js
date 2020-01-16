const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');

const route = '/token/revocation';

describe('revocation features', () => {
  before(bootstrap(__dirname));

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
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.AccessToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [correct hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
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
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [wrong hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
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
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes access token [unrecognized hint]', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
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
          this.provider.AccessToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('propagates exceptions on find', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
        scope: 'scope',
      });

      sinon.stub(this.provider.AccessToken, 'find').callsFake(async () => { throw new Error(); });

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          this.provider.AccessToken.find.restore();
        })
        .expect(500)
        .expect((response) => {
          expect(response.body.error).to.eql('server_error');
        });
    });

    it('revokes refresh token [no hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [correct hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
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
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [wrong hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
        scope: 'scope',
      });

      const stub = sinon.stub(this.provider.RefreshToken.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes refresh token [unrecognized hint]', async function () {
      const rt = new this.provider.RefreshToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client',
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
          this.provider.RefreshToken.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [no hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client',
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [correct hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client',
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'client_credentials' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [wrong hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client',
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'access_token' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
        })
        .expect(200)
        .expect('');
    });

    it('revokes client credentials token [unrecognized hint]', async function () {
      const rt = new this.provider.ClientCredentials({
        clientId: 'client',
      });

      const stub = sinon.stub(this.provider.ClientCredentials.prototype, 'destroy').callsFake(() => Promise.resolve());

      const token = await rt.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token, token_type_hint: 'foobar' })
        .type('form')
        .expect(() => {
          expect(stub.calledOnce).to.be.true;
          this.provider.ClientCredentials.prototype.destroy.restore();
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

    it('rejects wrong tokens', function () {
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
        })
        .type('form')
        .expect('')
        .expect(200);
    });

    it('does not revoke tokens of other clients', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client2',
        scope: 'scope',
      });

      const token = await at.save();
      return this.agent.post(route)
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.eql({
            error: 'invalid_request',
            error_description: 'this token does not belong to you',
          });
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
        .expect(() => {
          this.provider.AccessToken.find.restore();
        })
        .catch((err) => {
          this.provider.AccessToken.find.restore();
          throw err;
        });
    });

    describe('populates ctx.oidc.entities', () => {
      it('when revoking an AccessToken', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'AccessToken');
        }, done));

        (async () => {
          const at = new this.provider.AccessToken({
            accountId: 'accountId',
            grantId: 'foo',
            clientId: 'client',
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
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'RefreshToken');
        }, done));

        (async () => {
          const rt = new this.provider.RefreshToken({
            accountId: 'accountId',
            grantId: 'foo',
            clientId: 'client',
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
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'ClientCredentials');
        }, done));

        (async () => {
          const rt = new this.provider.ClientCredentials({
            clientId: 'client',
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
