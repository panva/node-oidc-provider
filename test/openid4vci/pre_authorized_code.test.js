import { expect } from 'chai';
import { createSandbox } from 'sinon';
import {
  SignJWT, exportJWK, generateKeyPair,
} from 'jose';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

const route = '/token';
const grant_type = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const sinon = createSandbox();

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code', () => {
  before(bootstrap(import.meta.url));
  afterEach(sinon.restore);

  async function mint({
    accountId = 'account',
    clientId = 'wallet',
    grantAccountId = accountId,
    grantId,
    scope = 'mdl_scope',
    oidcScope,
    txCode,
    rar,
  } = {}) {
    const resource = `${this.provider.issuer}${this.suitePath('/credential')}`;

    if (grantId === undefined) {
      const grant = new this.provider.Grant({ accountId: grantAccountId, clientId });
      grant.addResourceScope(resource, 'mdl_scope');
      if (oidcScope) {
        grant.addOIDCScope(oidcScope);
      }
      grantId = await grant.save();
    }

    const preAuthorizedCode = new this.provider.PreAuthorizedCode({
      accountId,
      clientId,
      grantId,
      resource,
      scope,
      txCode,
      rar,
    });

    return preAuthorizedCode.save();
  }

  it('is advertised in the discovery document', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body.grant_types_supported).to.include(grant_type);
      });
  });

  it('returns the right stuff', async function () {
    const spy = sinon.spy();
    this.provider.once('grant.success', spy);

    const code = await mint.call(this);

    return this.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        const jti = this.getTokenJti(code);
        const stored = this.TestAdapter.for('PreAuthorizedCode').syncFind(jti);
        expect(stored).to.have.property('consumed').and.be.most(epochTime());
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type', 'scope');
        expect(response.body).to.have.property('scope', 'mdl_scope');
        expect(response.body).to.have.property('token_type', 'Bearer');
      });
  });

  it('populates ctx.oidc.entities', function (done) {
    this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Client', 'Grant', 'Account', 'PreAuthorizedCode', 'AccessToken');
      expect(ctx.oidc.entities.AccessToken).to.have.property('gty', 'pre_authorized_code');
    }, done);

    mint.call(this).then((code) => {
      this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .end(() => {});
    });
  });

  it('issues a refresh token (w/ offline_access)', async function () {
    const code = await mint.call(this, {
      scope: 'offline_access mdl_scope',
      oidcScope: 'offline_access',
    });

    return this.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('refresh_token');
      });
  });

  it('passes authorization_details through to the token response', async function () {
    const rar = [{
      type: 'openid_credential',
      credential_configuration_id: 'org.iso.18013.5.1.mDL',
    }];
    const code = await mint.call(this, { rar });

    return this.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.deep.property('authorization_details', rar);
      });
  });

  it('can be used towards the credential endpoint', async function () {
    const code = await mint.call(this);

    const { body: { access_token: accessToken } } = await this.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200);

    const { body: { c_nonce: nonce } } = await this.agent.post('/challenge')
      .expect(200);

    const keypair = await generateKeyPair('ES256', { extractable: true });
    const proof = await new SignJWT({ aud: this.provider.issuer, nonce })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'openid4vci-proof+jwt',
        jwk: await exportJWK(keypair.publicKey),
      })
      .setIssuedAt()
      .sign(keypair.privateKey);

    return this.agent.post('/credential')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        credential_configuration_id: 'org.iso.18013.5.1.mDL',
        proofs: {
          jwt: [proof],
        },
      })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
      });
  });

  describe('validates', () => {
    it('grant type is allowed for the client', async function () {
      const code = await mint.call(this, { clientId: 'client' });

      return this.agent.post(route)
        .auth('client', 'secret')
        .type('form')
        .send({
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'requested grant type is not allowed for this client',
        });
    });

    it('pre-authorized_code param presence', function () {
      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          grant_type,
        })
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'invalid_request',
          error_description: "missing required parameter 'pre-authorized_code'",
        });
    });

    it('authorization_details parameter is not supported', async function () {
      const code = await mint.call(this);

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          authorization_details: JSON.stringify([{ type: 'openid_credential' }]),
        })
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'authorization_details is unsupported for this grant_type',
        });
    });

    it('code being "found"', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': 'foobar',
          grant_type,
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('pre-authorized code not found');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('code belongs to client', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const code = await mint.call(this, { clientId: 'wallet-other' });

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('client mismatch');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    context('', () => {
      before(function () {
        const { ttl } = i(this.provider).configuration;
        this.prev = ttl.PreAuthorizedCode;
        ttl.PreAuthorizedCode = 0;
      });

      after(function () {
        i(this.provider).configuration.ttl.PreAuthorizedCode = this.prev;
      });

      it('code is not expired', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        const code = await mint.call(this);

        return this.agent.post(route)
          .type('form')
          .send({
            client_id: 'wallet',
            'pre-authorized_code': code,
            grant_type,
          })
          .expect(400)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('pre-authorized code is expired');
          })
          .expect((response) => {
            expect(response.body).to.have.property('error', 'invalid_grant');
          });
      });
    });

    it('code is not already used', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const code = await mint.call(this);
      const preAuthorizedCode = await this.provider.PreAuthorizedCode.find(code);
      await preAuthorizedCode.consume();

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('pre-authorized code already consumed');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('account is still there', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const code = await mint.call(this, { accountId: 'notfound' });

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('pre-authorized code invalid (referenced account not found)');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('grant is still there', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const code = await mint.call(this, { grantId: 'foobar' });

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('grant not found');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('account matches the grant', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const code = await mint.call(this, { grantAccountId: 'other-account' });

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('accountId mismatch');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });
  });

  describe('Transaction Code', () => {
    it('is validated when attached to the code', async function () {
      const code = await mint.call(this, { txCode: '493536' });

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '493536',
        })
        .expect(200);
    });

    it('must be provided when attached to the code (without consuming it)', async function () {
      const code = await mint.call(this, { txCode: '493536' });

      await this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: "missing required parameter 'tx_code'",
        });

      const jti = this.getTokenJti(code);
      expect(this.TestAdapter.for('PreAuthorizedCode').syncFind(jti)).not.to.have.property('consumed');

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '493536',
        })
        .expect(200);
    });

    it('must match the one attached to the code (consuming it)', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      const code = await mint.call(this, { txCode: '493536' });

      await this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '635394',
        })
        .expect(400)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('invalid tx_code provided');
        })
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '493536',
        })
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('must not be provided when not attached to the code (without consuming it)', async function () {
      const code = await mint.call(this);

      await this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '493536',
        })
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'tx_code is not expected for this pre-authorized code',
        });

      const jti = this.getTokenJti(code);
      expect(this.TestAdapter.for('PreAuthorizedCode').syncFind(jti)).not.to.have.property('consumed');

      return this.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(200);
    });
  });
});
