import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
} from 'jose';
import { createSandbox } from 'sinon';
import epochTime from '../../lib/helpers/epoch_time.js';
import instance from '../../lib/helpers/weak_cache.js';
import bootstrap from '../test_helper.js';
import { rarEvents } from './openid4vci.config.js';

const route = '/token';
const grant_type = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const sinon = createSandbox();

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  async function mint({
    accountId = 'account',
    clientId = 'wallet',
    expiresIn,
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
      expiresIn,
      grantId,
      resource,
      scope,
      txCode,
      rar,
    });

    return preAuthorizedCode.save();
  }

  it('is advertised in the discovery document', { timeout: 3000 }, () => fixture.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        assert.ok(response.body.grant_types_supported.includes(grant_type));
      }));

  it('returns the right stuff', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture.provider.once('grant.success', spy);

    const code = await mint.call(fixture);

    return fixture.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
        const jti = fixture.getTokenJti(code);
        const stored = fixture.TestAdapter.for('PreAuthorizedCode').syncFind(jti);
        ((actual) => { assert.ok('consumed' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(value <= epochTime()); })(actual.consumed); })(stored);
      })
      .expect((response) => {
        assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'expires_in', 'token_type', 'scope']));
        ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'mdl_scope'); })(response.body);
        ((actual) => { assert.ok('token_type' in Object(actual)); assert.equal(actual.token_type, 'Bearer'); })(response.body);
      });
  });

  it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
    fixture.assertOnce((ctx) => {
      assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'Grant', 'Account', 'PreAuthorizedCode', 'AccessToken']));
      ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'pre_authorized_code'); })(ctx.oidc.entities.AccessToken);
    }, done);

    mint.call(fixture).then((code) => {
      fixture.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .end(() => {});
    });
  });

  it('filters removed Resource Server scopes when exchanging a pre-authorized code', { timeout: 3000 }, async () => {
    const code = await mint.call(fixture);
    sinon.stub(instance(fixture.provider).features.resourceIndicators, 'getResourceServerInfo')
      .callsFake((_ctx, resource) => ({ audience: resource, scope: 'other_scope' }));

    const { body } = await fixture.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200);

    ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, ''); })(body);
    const token = await fixture.provider.AccessToken.find(body.access_token);
    ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, ''); })(token);
  });

  it('issues a refresh token (w/ offline_access)', { timeout: 3000 }, async () => {
    const code = await mint.call(fixture, {
      scope: 'offline_access mdl_scope',
      oidcScope: 'offline_access',
    });

    return fixture.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200)
      .expect((response) => {
        assert.ok('refresh_token' in Object(response.body));
      });
  });

  it('does not issue an ID token when the source includes openid scope', { timeout: 3000 }, async () => {
    const code = await mint.call(fixture, {
      scope: 'openid offline_access mdl_scope',
      oidcScope: 'openid offline_access',
    });

    await fixture.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200)
      .expect(({ body }) => {
        assert.ok('refresh_token' in Object(body));
        assert.ok(!('id_token' in Object(body)));
      });
  });

  it('returns the authorization_details assigned to the access token', { timeout: 3000 }, async () => {
    const rar = [{
      type: 'openid_credential',
      credential_configuration_id: 'org.iso.18013.5.1.mDL',
    }];
    const code = await mint.call(fixture, { rar });

    return fixture.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200)
      .expect((response) => {
        ((actual) => { assert.ok('authorization_details' in Object(actual)); assert.deepEqual(actual.authorization_details, [{
          ...rar[0],
          credential_identifiers: ['org.iso.18013.5.1.mDL-id-1'],
        }]); })(response.body);
      });
  });

  it('can be used towards the credential endpoint', { timeout: 3000 }, async () => {
    const code = await mint.call(fixture);

    const { body: { access_token: accessToken } } = await fixture.agent.post(route)
      .type('form')
      .send({
        client_id: 'wallet',
        'pre-authorized_code': code,
        grant_type,
      })
      .expect(200);

    const { body: { c_nonce: nonce } } = await fixture.agent.post('/challenge')
      .expect(200);

    const keypair = await generateKeyPair('ES256', { extractable: true });
    const proof = await new SignJWT({ aud: fixture.provider.issuer, nonce })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'openid4vci-proof+jwt',
        jwk: await exportJWK(keypair.publicKey),
      })
      .setIssuedAt()
      .sign(keypair.privateKey);

    return fixture.agent.post('/credential')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        credential_configuration_id: 'org.iso.18013.5.1.mDL',
        proofs: {
          jwt: [proof],
        },
      })
      .expect(200)
      .expect((response) => {
        ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
      });
  });

  describe('validates', () => {
    const fixture1 = Object.create(fixture);

    it('grant type is allowed for the client', { timeout: 3000 }, async () => {
      const code = await mint.call(fixture1, { clientId: 'client' });

      return fixture1.agent.post(route)
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

    it('pre-authorized_code param presence', { timeout: 3000 }, () => fixture1.agent.post(route)
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
        }));

    it('accepts and narrows authorization_details', { timeout: 3000 }, async () => {
      const granted = [{
        type: 'openid_credential',
        credential_configuration_id: 'org.iso.18013.5.1.mDL',
      }, {
        type: 'openid_credential',
        credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
      }];
      const requested = [granted[1]];
      const code = await mint.call(fixture1, { rar: granted });
      const callback = new Promise((resolve) => {
        rarEvents.once('authorizationDetailsForAccessToken', (...args) => resolve(args));
      });

      const response = await fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          authorization_details: JSON.stringify(requested),
        })
        .expect(200);

      ((actual) => { assert.ok('authorization_details' in Object(actual)); assert.deepEqual(actual.authorization_details, [{
        ...requested[0],
        credential_identifiers: ['org.iso.18013.5.1.mDL.no_scope-id-1'],
      }]); })(response.body);

      const [, token, source, actualGrantType] = await callback;
      ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'AccessToken'); })(token);
      ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'PreAuthorizedCode'); })(source);
      assert.equal(actualGrantType, grant_type);
    });

    it('rejects authorization_details not present in the grant', { timeout: 3000 }, async () => {
      const code = await mint.call(fixture1, {
        rar: [{
          type: 'openid_credential',
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
        }],
      });

      return fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          authorization_details: JSON.stringify([{
            type: 'openid_credential',
            credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
          }]),
        })
        .expect(400)
        .expect({
          error: 'invalid_authorization_details',
          error_description: 'requested authorization details were not granted',
        });
    });

    it('code being "found"', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.once('grant.error', spy);

      return fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': 'foobar',
          grant_type,
        })
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'pre-authorized code not found');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('code belongs to client', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture1.provider.once('grant.error', spy);

      const code = await mint.call(fixture1, { clientId: 'wallet-other' });

      return fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'client mismatch');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    describe('', () => {
      const fixture2 = Object.create(fixture1);

      it('code is not expired', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once('grant.error', spy);

        const code = await mint.call(fixture2, { expiresIn: -1 });

        return fixture2.agent.post(route)
          .type('form')
          .send({
            client_id: 'wallet',
            'pre-authorized_code': code,
            grant_type,
          })
          .expect(400)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'pre-authorized code is expired');
          })
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          });
      });
    });

    it('code is not already used', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture1.provider.once('grant.error', spy);

      const code = await mint.call(fixture1);
      const preAuthorizedCode = await fixture1.provider.PreAuthorizedCode.find(code);
      await preAuthorizedCode.consume();

      return fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'pre-authorized code already consumed');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('account is still there', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture1.provider.once('grant.error', spy);

      const code = await mint.call(fixture1, { accountId: 'notfound' });

      return fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'pre-authorized code invalid (referenced account not found)');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('grant is still there', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture1.provider.once('grant.error', spy);

      const code = await mint.call(fixture1, { grantId: 'foobar' });

      return fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'grant not found');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('account matches the grant', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture1.provider.once('grant.error', spy);

      const code = await mint.call(fixture1, { grantAccountId: 'other-account' });

      return fixture1.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
        })
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'accountId mismatch');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });
  });

  describe('Transaction Code', () => {
    const fixture3 = Object.create(fixture);

    it('is validated when attached to the code', { timeout: 3000 }, async () => {
      const code = await mint.call(fixture3, { txCode: '493536' });

      return fixture3.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '493536',
        })
        .expect(200);
    });

    it('must be provided when attached to the code (without consuming it)', { timeout: 3000 }, async () => {
      const code = await mint.call(fixture3, { txCode: '493536' });

      await fixture3.agent.post(route)
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

      const jti = fixture3.getTokenJti(code);
      assert.ok(!('consumed' in Object(fixture3.TestAdapter.for('PreAuthorizedCode').syncFind(jti))));

      return fixture3.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '493536',
        })
        .expect(200);
    });

    it('must match the one attached to the code (consuming it)', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture3.provider.once('grant.error', spy);

      const code = await mint.call(fixture3, { txCode: '493536' });

      await fixture3.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '635394',
        })
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'invalid tx_code provided');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });

      return fixture3.agent.post(route)
        .type('form')
        .send({
          client_id: 'wallet',
          'pre-authorized_code': code,
          grant_type,
          tx_code: '493536',
        })
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('must not be provided when not attached to the code (without consuming it)', { timeout: 3000 }, async () => {
      const code = await mint.call(fixture3);

      await fixture3.agent.post(route)
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

      const jti = fixture3.getTokenJti(code);
      assert.ok(!('consumed' in Object(fixture3.TestAdapter.for('PreAuthorizedCode').syncFind(jti))));

      return fixture3.agent.post(route)
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
