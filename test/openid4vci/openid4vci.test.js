import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, hash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

import sinon from 'sinon';
import {
  SignJWT, exportJWK, generateKeyPair, calculateJwkThumbprint,
} from 'jose';

import Provider from '../../lib/index.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import { InvalidToken } from '../../lib/helpers/errors.js';
import getConfig from '../default.config.js';
import bootstrap from '../test_helper.js';

import { attesterKeypair } from './openid4vci.config.js';

const certificatePrivateKey = createPrivateKey(readFileSync(new URL('../jwks/ec.key', import.meta.url)));
const certificateKeypair = {
  privateKey: certificatePrivateKey,
  publicKey: createPublicKey(certificatePrivateKey),
};
const certificate = readFileSync(new URL('../jwks/ec.crt', import.meta.url), 'utf8')
  .replace(/-----(?:BEGIN|END) CERTIFICATE-----|\s/g, '');

function ath(accessToken) {
  return hash('sha256', accessToken, 'base64url');
}

async function credentialProof(keypair, issuer, {
  aud = issuer,
  iss,
  nonce,
  typ = 'openid4vci-proof+jwt',
  alg = 'ES256',
  kid,
  x5c,
  withIat = true,
  key_attestation,
} = {}) {
  const header = {
    alg,
    typ,
    jwk: await exportJWK(keypair.publicKey),
  };

  if (kid !== undefined) {
    header.kid = kid;
  }

  if (x5c !== undefined) {
    header.x5c = x5c;
  }

  if (key_attestation !== undefined) {
    header.key_attestation = key_attestation;
  }

  const jwt = new SignJWT({
    aud,
    iss,
    nonce,
  })
    .setProtectedHeader(header);

  if (withIat) {
    jwt.setIssuedAt();
  }

  return jwt.sign(keypair.privateKey);
}

async function keyAttestation(attestedKeys, {
  nonce,
  iss = 'https://wallet-provider.example.com',
  typ = 'key-attestation+jwt',
  alg = 'ES256',
  withIat = true,
  withIss = true,
  withAttestedKeys = true,
  withExp = false,
  signingKey = attesterKeypair.privateKey,
  key_storage,
  user_authentication,
  certification,
  kid,
} = {}) {
  const payload = {};
  if (nonce !== undefined) payload.nonce = nonce;
  if (withAttestedKeys) payload.attested_keys = attestedKeys;
  if (key_storage !== undefined) payload.key_storage = key_storage;
  if (user_authentication !== undefined) payload.user_authentication = user_authentication;
  if (certification !== undefined) payload.certification = certification;

  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg, typ, kid });

  if (withIss) {
    jwt.setIssuer(iss);
  }

  if (withIat) {
    jwt.setIssuedAt();
  }

  if (withExp) {
    jwt.setExpirationTime('1h');
  }

  return jwt.sign(signingKey);
}

async function DPoP(keypair, htu, htm, accessToken) {
  return new SignJWT({
    htu,
    htm,
    ath: ath(accessToken),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: await exportJWK(keypair.publicKey) })
    .setJti(randomUUID())
    .setIssuedAt()
    .sign(keypair.privateKey);
}

describe('features.openid4vci configuration', () => {
  it('requires jwk cryptographic binding when jwt proofs are supported', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256'],
            },
          },
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].cryptographic_binding_methods_supported must include 'jwk' when jwt proofs are supported")); return true; });
  });

  it('requires valid batch credential issuance metadata when configured', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      metadata: {
        batch_credential_issuance: {
          batch_size: 1,
        },
      },
      credentialConfigurationsSupported: {
        valid: {
          format: 'mso_mdoc',
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes('features.openid4vci.metadata.batch_credential_issuance.batch_size must be an integer greater than or equal to 2')); return true; });
  });

  it('rejects credential configuration with unsupported proof type', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          proof_types_supported: {
            cwt: {
              proof_signing_alg_values_supported: ['ES256'],
            },
          },
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported contains unsupported proof type(s): cwt")); return true; });
  });

  it('rejects credential configuration with unsupported cryptographic binding method', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          cryptographic_binding_methods_supported: ['jwk', 'cose_key'],
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].cryptographic_binding_methods_supported contains unsupported method(s): cose_key")); return true; });
  });

  it('rejects credential configuration with credential_response_encryption', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          credential_response_encryption: {
            alg_values_supported: ['ECDH-ES'],
            enc_values_supported: ['A128GCM'],
            encryption_required: false,
          },
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].credential_response_encryption is not supported")); return true; });
  });

  it('requires request encryption support with credentialResponseEncryption', { timeout: 3000 }, () => {
    const config = getConfig();
    config.features.encryption = { enabled: true };

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialResponseEncryption: {
        required: false,
      },
      credentialConfigurationsSupported: {
        valid: {
          format: 'mso_mdoc',
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes('features.openid4vci.credentialResponseEncryption requires credentialRequestEncryption')); return true; });
  });

  it('rejects key_attestations_required that is not a plain object', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          cryptographic_binding_methods_supported: ['jwk'],
          proof_types_supported: {
            attestation: {
              proof_signing_alg_values_supported: ['ES256'],
              key_attestations_required: 'not-an-object',
            },
          },
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required must be a plain object")); return true; });
  });

  it('rejects key_attestations_required.key_storage that is not a non-empty array of strings', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          cryptographic_binding_methods_supported: ['jwk'],
          proof_types_supported: {
            attestation: {
              proof_signing_alg_values_supported: ['ES256'],
              key_attestations_required: {
                key_storage: 'not-an-array',
              },
            },
          },
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required.key_storage must be a non-empty array of non-empty strings")); return true; });
  });

  it('rejects key_attestations_required.key_storage that is an empty array', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          cryptographic_binding_methods_supported: ['jwk'],
          proof_types_supported: {
            attestation: {
              proof_signing_alg_values_supported: ['ES256'],
              key_attestations_required: {
                key_storage: [],
              },
            },
          },
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required.key_storage must be a non-empty array of non-empty strings")); return true; });
  });

  it('rejects key_attestations_required.user_authentication that is not valid', { timeout: 3000 }, () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      credentialConfigurationsSupported: {
        invalid: {
          format: 'mso_mdoc',
          cryptographic_binding_methods_supported: ['jwk'],
          proof_types_supported: {
            attestation: {
              proof_signing_alg_values_supported: ['ES256'],
              key_attestations_required: {
                user_authentication: [123],
              },
            },
          },
        },
      },
    };

    assert.throws(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }, (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required.user_authentication must be a non-empty array of non-empty strings")); return true; });
  });
});

describe('features.openid4vci', () => {
  const fixture1 = {};

  before(bootstrap(import.meta.url, fixture1), { timeout: 3000 });

  it('exposes credential issuer metadata endpoint', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-credential-issuer')
      .expect(200)
      .expect((response) => {
        ((actual) => { assert.ok('credential_issuer' in Object(actual)); assert.match(actual.credential_issuer, /^http:\/\/127\.0\.0\.1:/); })(response.body);
        ((actual) => { assert.ok('credential_endpoint' in Object(actual)); assert.match(actual.credential_endpoint, /\/credential$/); })(response.body);
        ((actual) => { assert.ok('nonce_endpoint' in Object(actual)); assert.match(actual.nonce_endpoint, /\/challenge$/); })(response.body);
        ((actual) => { assert.ok('test_metadata_member' in Object(actual)); assert.equal(actual.test_metadata_member, 'test-value'); })(response.body);
        ((actual) => { assert.ok('batch_credential_issuance' in Object(actual)); assert.deepEqual(actual.batch_credential_issuance, { batch_size: 2 }); })(response.body);
        assert.ok('org.iso.18013.5.1.mDL' in Object(response.body.credential_configurations_supported));
        ((actual) => { assert.ok('format' in Object(actual)); assert.equal(actual.format, 'mso_mdoc'); })(response.body.credential_configurations_supported['org.iso.18013.5.1.mDL']);
        ((actual) => { assert.ok('cryptographic_binding_methods_supported' in Object(actual)); assert.deepEqual(actual.cryptographic_binding_methods_supported, ['jwk']); })(response.body.credential_configurations_supported['org.iso.18013.5.1.mDL']);
      }));

  describe('authorization_details validations', () => {
    const fixture2 = Object.create(fixture1);

    for (const verb of ['get', 'post']) {
      it(`rejects an unknown inherited authorization details type over ${verb}`, { timeout: 3000 }, () => {
        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code',
          authorization_details: JSON.stringify([
            {
              type: 'toString',
            },
          ]),
        });

        return fixture2.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_authorization_details'))
          .expect(auth.validateErrorDescription('unsupported authorization details type value (authorization details index 0)'));
      });
    }

    it('rejects openid_credential detail without credential_configuration_id', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        authorization_details: JSON.stringify([
          {
            type: 'openid_credential',
          },
        ]),
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_authorization_details'))
        .expect(auth.validateErrorDescription("'credential_configuration_id' must be a non-empty string"));
    });

    for (const credentialConfigurationId of ['not_found', 'toString']) {
      it(`rejects unknown credential_configuration_id ${credentialConfigurationId} in authorization details`, { timeout: 3000 }, () => {
        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code',
          authorization_details: JSON.stringify([
            {
              type: 'openid_credential',
              credential_configuration_id: credentialConfigurationId,
            },
          ]),
        });

        return fixture2.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_authorization_details'))
          .expect(auth.validateErrorDescription("'credential_configuration_id' must reference an entry in credential_configurations_supported"));
      });
    }

    it('rejects openid_credential claims path entries with invalid types', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        authorization_details: JSON.stringify([
          {
            type: 'openid_credential',
            credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
            claims: [
              {
                path: [{}],
              },
            ],
          },
        ]),
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_authorization_details'))
        .expect(auth.validateErrorDescription('claims description path entries must be non-empty strings, null, or non-negative integers'));
    });
  });

  describe('credential endpoint', () => {
    const fixture3 = Object.create(fixture1);

    before(() => {
      const credentialResource = `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`;

      return fixture3.login({
        scope: 'mdl_scope',
        resources: {
          [credentialResource]: 'mdl_scope',
        },
      });
    }, { timeout: 3000 });
    after(() => fixture3.logout(), { timeout: 3000 });
    before(async () => {
      fixture3.keypair = await generateKeyPair('ES256', { extractable: true });
      fixture3.thumbprint = await calculateJwkThumbprint(await exportJWK(fixture3.keypair.publicKey));
      fixture3.otherKeypair = await generateKeyPair('ES256', { extractable: true });
    }, { timeout: 3000 });

    async function getAccessToken() {
      const ac = new this.provider.AuthorizationCode({
        accountId: this.loggedInAccountId,
        authTime: epochTime(),
        clientId: 'client',
        grantId: this.getGrantId('client'),
        redirectUri: 'https://client.example.com/cb',
        resource: `${this.provider.issuer}${this.suitePath('/credential')}`,
        scope: 'mdl_scope',
      });

      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          redirect_uri: 'https://client.example.com/cb',
          grant_type: 'authorization_code',
          code: await ac.save(),
        })
        .expect(200);

      return response.body.access_token;
    }

    async function getSenderConstrainedAccessToken() {
      const at = new this.provider.AccessToken({
        accountId: this.loggedInAccountId,
        aud: `${this.provider.issuer}${this.suitePath('/credential')}`,
        client: await this.provider.Client.find('client'),
        grantId: this.getGrantId('client'),
        scope: 'mdl_scope',
      });
      at.setThumbprint('jkt', this.thumbprint);

      return at.save();
    }

    async function getRarAccessToken(credentialConfigurationId) {
      const at = new this.provider.AccessToken({
        accountId: this.loggedInAccountId,
        aud: `${this.provider.issuer}${this.suitePath('/credential')}`,
        client: await this.provider.Client.find('client'),
        grantId: this.getGrantId('client'),
        rar: [{
          type: 'openid_credential',
          credential_configuration_id: credentialConfigurationId,
        }],
      });

      return at.save();
    }

    async function getRarAccessTokenWithIdentifiers(
      credentialConfigurationId,
      credentialIdentifiers,
    ) {
      const at = new this.provider.AccessToken({
        accountId: this.loggedInAccountId,
        aud: `${this.provider.issuer}${this.suitePath('/credential')}`,
        client: await this.provider.Client.find('client'),
        grantId: this.getGrantId('client'),
        rar: [{
          type: 'openid_credential',
          credential_configuration_id: credentialConfigurationId,
          credential_identifiers: credentialIdentifiers,
        }],
      });

      return at.save();
    }

    async function getCNonce() {
      const response = await this.agent.post('/challenge')
        .expect(200);

      return response.body.c_nonce;
    }

    async function expectCredentialTokenError(accessToken, errorDetail, expectedEntities) {
      const spy = sinon.spy();
      this.provider.once('credential.error', spy);

      await this.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
        })
        .expect(401)
        .expect({
          error: 'invalid_token',
          error_description: 'invalid token provided',
        });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      assert.ok(spy.args[0][1] instanceof InvalidToken);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, errorDetail); })(spy.args[0][1]);
      assert.deepEqual(Object.keys(spy.args[0][0].oidc.entities), expectedEntities);
    }

    it('issues credentials through configured helper', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
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
          assert.ok('credential' in Object(response.body.credentials[0]));
        });
    });

    it('populates access token entities in dependency order', { timeout: 3000 }, (_t, done) => {
      (async () => {
        const accessToken = await getAccessToken.call(fixture3);
        const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
          nonce: await getCNonce.call(fixture3),
        });

        fixture3.assertOnce((ctx) => {
          assert.deepEqual(Object.keys(ctx.oidc.entities), [
            'AccessToken',
            'Client',
            'Account',
            'Grant',
          ]);
        }, done);

        await fixture3.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(200);
      })().catch(done);
    });

    it('rejects unknown access tokens', { timeout: 3000 }, () => expectCredentialTokenError.call(
        fixture3,
        'Loremipsumdolorsitametconsecteturadipisicingelitsed',
        'access token not found',
        [],
      ));

    it('rejects access tokens whose client no longer exists', { timeout: 3000 }, async () => {
      const accessToken = await new fixture3.provider.AccessToken({
        accountId: fixture3.loggedInAccountId,
        aud: `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`,
        clientId: 'missing-client',
        expiresIn: 300,
        grantId: fixture3.getGrantId('client'),
        scope: 'mdl_scope',
      }).save();

      await expectCredentialTokenError.call(
        fixture3,
        accessToken,
        'associated client not found',
        ['AccessToken'],
      );
    });

    it('rejects access tokens whose account no longer exists', { timeout: 3000 }, async () => {
      const accessToken = await new fixture3.provider.AccessToken({
        accountId: 'notfound',
        aud: `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`,
        client: await fixture3.provider.Client.find('client'),
        grantId: fixture3.getGrantId('client'),
        scope: 'mdl_scope',
      }).save();

      await expectCredentialTokenError.call(
        fixture3,
        accessToken,
        'associated account not found',
        ['AccessToken', 'Client'],
      );
    });

    it('rejects access tokens whose grant no longer exists', { timeout: 3000 }, async () => {
      const accessToken = await new fixture3.provider.AccessToken({
        accountId: fixture3.loggedInAccountId,
        aud: `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`,
        client: await fixture3.provider.Client.find('client'),
        grantId: 'missing-grant',
        scope: 'mdl_scope',
      }).save();

      await expectCredentialTokenError.call(
        fixture3,
        accessToken,
        'grant not found',
        ['AccessToken', 'Client', 'Account'],
      );
    });

    it('issues c_nonce from challenge endpoint', { timeout: 3000 }, () => fixture3.agent.post('/challenge')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('c_nonce' in Object(actual)); assert.equal(typeof actual.c_nonce, 'string'); assert.notEqual(actual.c_nonce.length, 0); })(response.body);
        }));

    it('challenges with Bearer and DPoP when no access token is provided', { timeout: 3000 }, async () => fixture3.agent.post('/credential')
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
        })
        .expect(401)
        .expect({
          error: 'invalid_token',
          error_description: 'no access token provided',
        })
        .expect('WWW-Authenticate', /Bearer realm=/)
        .expect('WWW-Authenticate', /DPoP realm=/)
        .expect('WWW-Authenticate', /algs="ES256"/));

    it('supports sender-constrained DPoP access tokens', { timeout: 3000 }, async () => {
      const accessToken = await getSenderConstrainedAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });
      const htu = `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`;

      return fixture3.agent.post('/credential')
        .set('Authorization', `DPoP ${accessToken}`)
        .set('DPoP', await DPoP(fixture3.keypair, htu, 'POST', accessToken))
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

    it('rejects DPoP authorization scheme without DPoP header', { timeout: 3000 }, async () => {
      const accessToken = await getSenderConstrainedAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `DPoP ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: '`DPoP` header not provided',
        });
    });

    it('rejects Bearer authorization when DPoP header is provided', { timeout: 3000 }, async () => {
      const accessToken = await getSenderConstrainedAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });
      const htu = `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`;

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('DPoP', await DPoP(fixture3.keypair, htu, 'POST', accessToken))
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'authorization header scheme must be `DPoP` when DPoP is used',
        });
    });

    it('rejects sender-constrained token when DPoP key does not match jkt', { timeout: 3000 }, async () => {
      const accessToken = await getSenderConstrainedAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });
      const htu = `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`;

      return fixture3.agent.post('/credential')
        .set('Authorization', `DPoP ${accessToken}`)
        .set('DPoP', await DPoP(fixture3.otherKeypair, htu, 'POST', accessToken))
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(401)
        .expect({
          error: 'invalid_token',
          error_description: 'invalid token provided',
        });
    });

    it('rejects replayed DPoP proof JWTs', { timeout: 3000 }, async () => {
      const accessToken = await getSenderConstrainedAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });
      const htu = `${fixture3.provider.issuer}${fixture3.suitePath('/credential')}`;
      const dpop = await DPoP(fixture3.keypair, htu, 'POST', accessToken);

      await fixture3.agent.post('/credential')
        .set('Authorization', `DPoP ${accessToken}`)
        .set('DPoP', dpop)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(200);

      const spy = sinon.spy();
      fixture3.provider.once('credential.error', spy);
      await fixture3.agent.post('/credential')
        .set('Authorization', `DPoP ${accessToken}`)
        .set('DPoP', dpop)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(401)
        .expect({
          error: 'invalid_token',
          error_description: 'invalid token provided',
        });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      assert.ok(spy.args[0][1] instanceof InvalidToken);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'DPoP proof JWT Replay detected'); })(spy.args[0][1]);
    });

    describe('access token audience', () => {
      const fixture4 = Object.create(fixture3);

      const aliasAudience = 'https://mtls.op.example.com/credential';

      async function getAccessTokenWithAudience(aud) {
        const at = new this.provider.AccessToken({
          accountId: this.loggedInAccountId,
          aud,
          client: await this.provider.Client.find('client'),
          grantId: this.getGrantId('client'),
          scope: 'mdl_scope',
        });

        return at.save();
      }

      it('rejects access tokens with a different audience', { timeout: 3000 }, async () => {
        const accessToken = await getAccessTokenWithAudience.call(fixture4, aliasAudience);

        const spy = sinon.spy();
        fixture4.provider.once('credential.error', spy);

        await fixture4.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
          })
          .expect(401)
          .expect({
            error: 'invalid_token',
            error_description: 'invalid token provided',
          });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'token audience prevents accessing the credential endpoint'); })(spy.args[0][1]);
      });

      describe('with a credentialEndpointExpectedAudience helper', () => {
        const fixture5 = Object.create(fixture4);

        before(() => {
          fixture5.orig = i(fixture5.provider).features.openid4vci.credentialEndpointExpectedAudience;
          i(fixture5.provider).features.openid4vci.credentialEndpointExpectedAudience = () => aliasAudience;
        }, { timeout: 3000 });
        after(() => {
          i(fixture5.provider).features.openid4vci.credentialEndpointExpectedAudience = fixture5.orig;
        }, { timeout: 3000 });

        it('accepts the audience the helper returns', { timeout: 3000 }, async () => {
          const accessToken = await getAccessTokenWithAudience.call(fixture5, aliasAudience);
          const proof = await credentialProof(fixture5.keypair, fixture5.provider.issuer, {
            nonce: await getCNonce.call(fixture5),
          });

          return fixture5.agent.post('/credential')
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

        it('rejects the credential endpoint url the default would have accepted', { timeout: 3000 }, async () => {
          const accessToken = await getAccessTokenWithAudience.call(fixture5, `${fixture5.provider.issuer}${fixture5.suitePath('/credential')}`);

          const spy = sinon.spy();
          fixture5.provider.once('credential.error', spy);

          await fixture5.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL',
            })
            .expect(401)
            .expect({
              error: 'invalid_token',
              error_description: 'invalid token provided',
            });

          ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
          ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'token audience prevents accessing the credential endpoint'); })(spy.args[0][1]);
        });
      });

      describe('with a credentialEndpointExpectedAudience helper returning a non-string', () => {
        const fixture6 = Object.create(fixture4);

        before(() => {
          fixture6.orig = i(fixture6.provider).features.openid4vci.credentialEndpointExpectedAudience;
          i(fixture6.provider).features.openid4vci.credentialEndpointExpectedAudience = () => undefined;
        }, { timeout: 3000 });
        after(() => {
          i(fixture6.provider).features.openid4vci.credentialEndpointExpectedAudience = fixture6.orig;
        }, { timeout: 3000 });

        it('is a server_error', { timeout: 3000 }, async () => {
          const accessToken = await getAccessTokenWithAudience.call(fixture6, aliasAudience);

          const spy = sinon.spy();
          fixture6.provider.once('server_error', spy);

          await fixture6.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL',
            })
            .expect(500);

          ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'features.openid4vci.credentialEndpointExpectedAudience must return a string'); })(spy.args[0][1]);
        });
      });
    });

    it('returns unknown_credential_configuration for unknown ids', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'not_found',
        })
        .expect(400)
        .expect({
          error: 'unknown_credential_configuration',
          error_description: 'requested credential_configuration_id is unknown',
        });
    });

    it('does not treat an inherited property as a credential configuration', { timeout: 3000 }, async () => {
      const accessToken = await getRarAccessToken.call(fixture3, 'toString');

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'toString',
        })
        .expect(400)
        .expect({
          error: 'unknown_credential_configuration',
          error_description: 'requested credential_configuration_id is unknown',
        });
    });

    it('rejects a JSON null credential request', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Content-Type', 'application/json')
        .send('null')
        .expect(400)
        .expect({
          error: 'invalid_credential_request',
          error_description: 'credential request body must be a JSON object',
        });
    });

    it('supports full authorization code flow with scope for scoped configuration', { timeout: 3000 }, async () => {
      const auth = new fixture3.AuthorizationRequest({
        response_type: 'code',
        scope: 'mdl_scope',
      });

      let location;
      await fixture3.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect((response) => {
          ({ location } = response.headers);
        });

      if (/^\/interaction\//.test(location)) {
        await fixture3.agent.post(location)
          .send({ prompt: 'consent' })
          .type('form')
          .expect(303)
          .expect(({ headers }) => {
            ({ location } = headers);
          })
          .expect('location', /\/auth\//);

        await fixture3.agent.get(new URL(location, fixture3.provider.issuer).pathname)
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']));
      } else {
        auth.validatePresence(['code', 'state'])({ headers: { location } });
      }

      const tokenResponse = await fixture3.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'authorization_code',
          code: auth.res.code,
          code_verifier: auth.code_verifier,
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200);

      assert.ok(!('authorization_details' in Object(tokenResponse.body)));

      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${tokenResponse.body.access_token}`)
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

    it('supports full authorization code flow with authorization_details for no-scope configuration', { timeout: 3000 }, async () => {
      const authorizationDetails = [{
        type: 'openid_credential',
        credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
      }];

      const auth = new fixture3.AuthorizationRequest({
        response_type: 'code',

        authorization_details: JSON.stringify(authorizationDetails),
      });

      let location;
      await fixture3.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect((response) => {
          ({ location } = response.headers);
        })
        .expect('location', new RegExp(`^${fixture3.suitePath('/interaction/')}`));

      await fixture3.agent.post(location)
        .send({ prompt: 'consent' })
        .type('form')
        .expect(303)
        .expect(({ headers }) => {
          ({ location } = headers);
        })
        .expect('location', /\/auth\//);

      await fixture3.agent.get(new URL(location, fixture3.provider.issuer).pathname)
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']));

      const tokenResponse = await fixture3.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'authorization_code',
          code: auth.res.code,
          code_verifier: auth.code_verifier,
          redirect_uri: 'https://client.example.com/cb',
          authorization_details: JSON.stringify(authorizationDetails),
        })
        .expect(200);

      ((actual) => { assert.ok('authorization_details' in Object(actual)); assert.deepEqual(actual.authorization_details, [{
        ...authorizationDetails[0],
        credential_identifiers: ['org.iso.18013.5.1.mDL.no_scope-id-1'],
      }]); })(tokenResponse.body);

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${tokenResponse.body.access_token}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
        })
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
        });
    });

    it('supports full authorization code flow with credential_identifier', { timeout: 3000 }, async () => {
      const authorizationDetails = [{
        type: 'openid_credential',
        credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
      }];

      const auth = new fixture3.AuthorizationRequest({
        response_type: 'code',
        authorization_details: JSON.stringify(authorizationDetails),
      });

      let location;
      await fixture3.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect((response) => {
          ({ location } = response.headers);
        })
        .expect('location', new RegExp(`^${fixture3.suitePath('/interaction/')}`));

      await fixture3.agent.post(location)
        .send({ prompt: 'consent' })
        .type('form')
        .expect(303)
        .expect(({ headers }) => {
          ({ location } = headers);
        })
        .expect('location', /\/auth\//);

      await fixture3.agent.get(new URL(location, fixture3.provider.issuer).pathname)
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']));

      const tokenResponse = await fixture3.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'authorization_code',
          code: auth.res.code,
          code_verifier: auth.code_verifier,
          redirect_uri: 'https://client.example.com/cb',
          authorization_details: JSON.stringify(authorizationDetails),
        })
        .expect(200);

      assert.ok('authorization_details' in Object(tokenResponse.body));
      const returnedDetails = tokenResponse.body.authorization_details;
      ((actual) => { assert.ok(Array.isArray(actual)); assert.equal(actual.length, 1); })(returnedDetails);
      ((actual) => { assert.ok('credential_identifiers' in Object(actual)); assert.ok(Array.isArray(actual.credential_identifiers)); assert.notEqual(actual.credential_identifiers.length, 0); })(returnedDetails[0]);

      const [credentialIdentifier] = returnedDetails[0].credential_identifiers;

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${tokenResponse.body.access_token}`)
        .send({
          credential_identifier: credentialIdentifier,
        })
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
          const issued = JSON.parse(response.body.credentials[0].credential);
          ((actual) => { assert.ok('credential_identifier' in Object(actual)); assert.equal(actual.credential_identifier, credentialIdentifier); })(issued);
        });
    });

    it('denies no-scope credential configuration without matching authorization_details', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
        })
        .expect(400)
        .expect({
          error: 'credential_request_denied',
          error_description: 'access token does not authorize issuance for requested credential configuration',
        });
    });

    it('allows no-scope credential configuration with matching authorization_details', { timeout: 3000 }, async () => {
      const accessToken = await getRarAccessToken.call(fixture3, 'org.iso.18013.5.1.mDL.no_scope');

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
        })
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
        });
    });

    it('issues credentials using credential_identifier from authorization_details', { timeout: 3000 }, async () => {
      const accessToken = await getRarAccessTokenWithIdentifiers.call(
        fixture3,
        'org.iso.18013.5.1.mDL.no_scope',
        ['CivilEngineeringDegree-2023'],
      );

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_identifier: 'CivilEngineeringDegree-2023',
        })
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
          const issued = JSON.parse(response.body.credentials[0].credential);
          ((actual) => { assert.ok('format' in Object(actual)); assert.equal(actual.format, 'org.iso.18013.5.1.mDL.no_scope'); })(issued);
          ((actual) => { assert.ok('credential_identifier' in Object(actual)); assert.equal(actual.credential_identifier, 'CivilEngineeringDegree-2023'); })(issued);
        });
    });

    it('issues credentials using credential_identifier with proofs', { timeout: 3000 }, async () => {
      const accessToken = await getRarAccessTokenWithIdentifiers.call(
        fixture3,
        'org.iso.18013.5.1.mDL',
        ['mDL-instance-1'],
      );
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_identifier: 'mDL-instance-1',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
          const issued = JSON.parse(response.body.credentials[0].credential);
          ((actual) => { assert.ok('format' in Object(actual)); assert.equal(actual.format, 'org.iso.18013.5.1.mDL'); })(issued);
          ((actual) => { assert.ok('credential_identifier' in Object(actual)); assert.equal(actual.credential_identifier, 'mDL-instance-1'); })(issued);
        });
    });

    it('does not resolve a credential_identifier to an inherited configuration property', { timeout: 3000 }, async () => {
      const accessToken = await getRarAccessTokenWithIdentifiers.call(
        fixture3,
        'toString',
        ['inherited-configuration'],
      );

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_identifier: 'inherited-configuration',
        })
        .expect(400)
        .expect({
          error: 'unknown_credential_configuration',
          error_description: 'credential configuration referenced by credential_identifier is unknown',
        });
    });

    it('returns unknown_credential_identifier when credential_identifier is not in access token', { timeout: 3000 }, async () => {
      const accessToken = await getRarAccessToken.call(fixture3, 'org.iso.18013.5.1.mDL.no_scope');

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_identifier: 'not-in-token',
        })
        .expect(400)
        .expect({
          error: 'unknown_credential_identifier',
          error_description: 'credential_identifier not found in the access token authorization details',
        });
    });

    it('returns unknown_credential_identifier when access token has no authorization_details', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_identifier: 'not-in-token',
        })
        .expect(400)
        .expect({
          error: 'unknown_credential_identifier',
          error_description: 'credential_identifier not found in the access token authorization details',
        });
    });

    it('returns invalid_proof when proofs are required but missing', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'proofs are required for this credential configuration',
        });
    });

    it('returns invalid_proof when JWT proof nonce is missing', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer);

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof nonce must be present',
        });
    });

    it('returns invalid_proof when JWT proof iat is missing', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
        withIat: false,
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof iat must be present',
        });
    });

    it('returns invalid_nonce when JWT proof nonce is present but invalid', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: 'invalid-nonce-value',
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_nonce',
          error_description: 'jwt proof nonce is invalid, retrieve a new c_nonce from the nonce endpoint',
        });
    });

    it('accepts a single proof object', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proof: {
            proof_type: 'jwt',
            jwt: proof,
          },
        })
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
        });
    });

    it('accepts multiple jwt proofs up to configured batch_size', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const nonce = await getCNonce.call(fixture3);
      const proofOne = await credentialProof(fixture3.keypair, fixture3.provider.issuer, { nonce });
      const proofTwo = await credentialProof(fixture3.otherKeypair, fixture3.provider.issuer, { nonce });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proofOne, proofTwo],
          },
        })
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
        });
    });

    it('returns invalid_proof when jwt proof batch exceeds configured batch_size', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const nonce = await getCNonce.call(fixture3);
      const proofOne = await credentialProof(fixture3.keypair, fixture3.provider.issuer, { nonce });
      const proofTwo = await credentialProof(fixture3.otherKeypair, fixture3.provider.issuer, { nonce });
      const thirdKeypair = await generateKeyPair('ES256', { extractable: true });
      const proofThree = await credentialProof(thirdKeypair, fixture3.provider.issuer, { nonce });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proofOne, proofTwo, proofThree],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof batch exceeds configured batch_size (2)',
        });
    });

    it('rejects using proof and proofs together', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proof: {
            proof_type: 'jwt',
            jwt: proof,
          },
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_credential_request',
          error_description: 'proof and proofs cannot be used together',
        });
    });

    it('returns invalid_proof for multiple proof types', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
            cwt: ['proof-cwt-1'],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'exactly one proof type must be provided in proofs',
        });
    });

    it('returns invalid_proof for invalid JWT proof typ', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
        typ: 'JWT',
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof typ must be openid4vci-proof+jwt',
        });
    });

    it('returns invalid_proof when JWT proof has both jwk and kid headers', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        kid: 'wallet-key',
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof must use exactly one of kid, jwk, or x5c',
        });
    });

    it('returns invalid_proof when JWT proof has both jwk and x5c headers', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(certificateKeypair, fixture3.provider.issuer, {
        nonce: await getCNonce.call(fixture3),
        x5c: [certificate],
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof must use exactly one of kid, jwk, or x5c',
        });
    });

    it('returns invalid_proof for JWT proof with aud mismatch', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        aud: 'https://attacker.example.com',
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof aud must equal credential issuer identifier',
        });
    });

    it('returns invalid_proof when JWT proof aud is not a string', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        aud: [fixture3.provider.issuer],
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof aud must be a string',
        });
    });

    it('returns invalid_proof when JWT proof iss does not match the client_id', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const proof = await credentialProof(fixture3.keypair, fixture3.provider.issuer, {
        iss: 'attacker',
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof iss must equal client_id',
        });
    });

    it('returns invalid_proof for JWT proof alg not supported by credential configuration', { timeout: 3000 }, async () => {
      const accessToken = await getAccessToken.call(fixture3);
      const p384 = await generateKeyPair('ES384', { extractable: true });
      const proof = await credentialProof(p384, fixture3.provider.issuer, {
        alg: 'ES384',
        nonce: await getCNonce.call(fixture3),
      });

      return fixture3.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(400)
        .expect({
          error: 'invalid_proof',
          error_description: 'jwt proof alg is not supported for this credential configuration',
        });
    });

    describe('jwt proof with key_attestation header', () => {
      const fixture7 = Object.create(fixture3);

      it('resolves a trusted key_attestation key by kid when iss is omitted', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const ka = await keyAttestation([await exportJWK(fixture7.keypair.publicKey)], {
          withExp: true,
          withIss: false,
          kid: 'trusted-attester',
        });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: { jwt: [proof] },
          })
          .expect(200);
      });

      it('issues credentials with a valid key_attestation in jwt proof header', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [
          { kty: 'urn:example:unrecognized-key-type' },
          await exportJWK(fixture7.keypair.publicKey),
        ];
        const ka = await keyAttestation(attestedKeys, { withExp: true });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
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
            const issued = JSON.parse(response.body.credentials[0].credential);
            ((actual) => { assert.ok('proof_type' in Object(actual)); assert.equal(actual.proof_type, 'jwt'); })(issued);
            ((actual) => { assert.ok('attested_keys_count' in Object(actual)); assert.equal(actual.attested_keys_count, 2); })(issued);
          });
      });

      it('rejects key_attestation without exp', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys);
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof key_attestation exp must be present',
          });
      });

      it('rejects key_attestation when jwt proof jwk is not among attested keys', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const otherKeys = [await exportJWK(fixture7.otherKeypair.publicKey)];
        const ka = await keyAttestation(otherKeys, { withExp: true });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof jwk is not among the attested keys in key_attestation',
          });
      });

      it('rejects key_attestation with invalid signature', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const wrongKey = await generateKeyPair('ES256', { extractable: true });
        const ka = await keyAttestation(attestedKeys, {
          withExp: true, signingKey: wrongKey.privateKey,
        });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof key_attestation signature verification failed',
          });
      });

      it('rejects key_attestation with wrong typ', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, { withExp: true, typ: 'JWT' });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof key_attestation typ must be key-attestation+jwt',
          });
      });

      it('rejects key_attestation with missing iat', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, { withExp: true, withIat: false });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof key_attestation iat must be present',
          });
      });

      it('rejects key_attestation with unknown issuer', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          iss: 'https://unknown-provider.example.com',
        });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof key_attestation signature verification failed',
          });
      });

      it('rejects when key_attestations_required but no key_attestation header', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, { nonce });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.jwt.attestation_required',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof must include a key_attestation header when key attestations are required',
          });
      });

      it('issues credentials when key_attestations_required and attestation meets requirements', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          key_storage: ['iso_18045_moderate'],
          user_authentication: ['iso_18045_moderate'],
        });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.jwt.attestation_required',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(200)
          .expect((response) => {
            ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
          });
      });

      it('rejects when key_attestation key_storage does not meet requirements', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          key_storage: ['iso_18045_basic'],
          user_authentication: ['iso_18045_moderate'],
        });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.jwt.attestation_required',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof key_attestation key_storage does not meet the credential configuration requirements',
          });
      });

      it('rejects when key_attestation user_authentication is missing but required', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [await exportJWK(fixture7.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          key_storage: ['iso_18045_high'],
        });
        const proof = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.jwt.attestation_required',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'jwt proof key_attestation user_authentication does not meet the credential configuration requirements',
          });
      });

      it('requires all batch jwt proofs to reference the same key_attestation', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [
          await exportJWK(fixture7.keypair.publicKey),
          await exportJWK(fixture7.otherKeypair.publicKey),
        ];
        const ka1 = await keyAttestation(attestedKeys, { withExp: true });
        const ka2 = await keyAttestation(attestedKeys, { withExp: true });
        const proof1 = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka1,
        });
        const proof2 = await credentialProof(fixture7.otherKeypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka2,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof1, proof2],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'all jwt proofs in a batch must reference the same key_attestation',
          });
      });

      it('accepts batch jwt proofs with the same key_attestation', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture7);
        const nonce = await getCNonce.call(fixture7);
        const attestedKeys = [
          await exportJWK(fixture7.keypair.publicKey),
          await exportJWK(fixture7.otherKeypair.publicKey),
        ];
        const ka = await keyAttestation(attestedKeys, { withExp: true });
        const proof1 = await credentialProof(fixture7.keypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });
        const proof2 = await credentialProof(fixture7.otherKeypair, fixture7.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return fixture7.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof1, proof2],
            },
          })
          .expect(200)
          .expect((response) => {
            ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
            const issued = JSON.parse(response.body.credentials[0].credential);
            ((actual) => { assert.ok('attested_keys_count' in Object(actual)); assert.equal(actual.attested_keys_count, 2); })(issued);
          });
      });
    });

    describe('attestation proof type', () => {
      const fixture8 = Object.create(fixture3);

      it('resolves a trusted attestation proof key by kid when iss is omitted', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestation = await keyAttestation([await exportJWK(fixture8.keypair.publicKey)], {
          nonce,
          withIss: false,
          kid: 'trusted-attester',
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: { attestation: [attestation] },
          })
          .expect(200);
      });

      it('still verifies the attestation signature when iss is omitted', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestation = await keyAttestation([await exportJWK(fixture8.keypair.publicKey)], {
          nonce,
          withIss: false,
          kid: 'trusted-attester',
          signingKey: fixture8.otherKeypair.privateKey,
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: { attestation: [attestation] },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof signature verification failed',
          });
      });

      it('issues credentials with a valid attestation proof', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(200)
          .expect((response) => {
            ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
            const issued = JSON.parse(response.body.credentials[0].credential);
            ((actual) => { assert.ok('proof_type' in Object(actual)); assert.equal(actual.proof_type, 'attestation'); })(issued);
            ((actual) => { assert.ok('attested_keys_count' in Object(actual)); assert.equal(actual.attested_keys_count, 1); })(issued);
          });
      });

      it('ignores public JWK members for other key types', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const publicJwk = await exportJWK(fixture8.keypair.publicKey);
        publicJwk.priv = 'an extension member for this key type';
        const attestation = await keyAttestation([publicJwk], { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(200);
      });

      it('allows unrecognized JWK key types', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [{ kty: 'urn:example:unrecognized-key-type' }];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(200)
          .expect((response) => {
            const issued = JSON.parse(response.body.credentials[0].credential);
            ((actual) => { assert.ok('attested_keys_count' in Object(actual)); assert.equal(actual.attested_keys_count, 1); })(issued);
          });
      });

      it('issues credentials with multiple attested keys', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [
          await exportJWK(fixture8.keypair.publicKey),
          await exportJWK(fixture8.otherKeypair.publicKey),
        ];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(200)
          .expect((response) => {
            ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
            const issued = JSON.parse(response.body.credentials[0].credential);
            ((actual) => { assert.ok('attested_keys_count' in Object(actual)); assert.equal(actual.attested_keys_count, 2); })(issued);
          });
      });

      it('accepts a single attestation proof object', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proof: {
              proof_type: 'attestation',
              attestation,
            },
          })
          .expect(200)
          .expect((response) => {
            ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
          });
      });

      it('rejects attestation proof with missing nonce', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys);

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof nonce must be present',
          });
      });

      it('rejects attestation proof with invalid nonce', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce: 'invalid-nonce-value',
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_nonce',
            error_description:
              'attestation proof nonce is invalid, retrieve a new c_nonce from the nonce endpoint',
          });
      });

      it('rejects attestation proof with missing iat', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          withIat: false,
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof iat must be present',
          });
      });

      it('rejects attestation proof with wrong typ', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          typ: 'JWT',
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof typ must be key-attestation+jwt',
          });
      });

      it('rejects attestation proof with invalid signature', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const wrongKey = await generateKeyPair('ES256', { extractable: true });
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          signingKey: wrongKey.privateKey,
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof signature verification failed',
          });
      });

      it('rejects attestation proof with unsupported alg', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const p384 = await generateKeyPair('ES384', { extractable: true });
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          alg: 'ES384',
          signingKey: p384.privateKey,
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description:
              'attestation proof alg is not supported for this credential configuration',
          });
      });

      it('rejects multiple attestation JWTs in proofs', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation1 = await keyAttestation(attestedKeys, { nonce });
        const attestation2 = await keyAttestation(attestedKeys, { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation1, attestation2],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'proofs.attestation must contain exactly one key attestation JWT',
          });
      });

      it('rejects attestation proof with empty attested_keys', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestation = await keyAttestation([], { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof attested_keys must be a non-empty array',
          });
      });

      it('rejects attestation proof with non-object attested_keys entries', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestation = await keyAttestation(['not-an-object'], { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof attested_keys entries must be JWK objects',
          });
      });

      it('rejects attested keys without a key type', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestation = await keyAttestation([{}], { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof attested_keys entries must be public asymmetric JWKs',
          });
      });

      it('rejects attested keys missing required public members', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestation = await keyAttestation([{
          kty: 'EC',
          crv: 'P-256',
          x: 'AQ',
        }], { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof attested_keys entries must be public asymmetric JWKs',
          });
      });

      it('rejects attestation proof with a private JWK in attested_keys', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const privateJwk = await exportJWK(fixture8.keypair.privateKey);
        const attestation = await keyAttestation([privateJwk], { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof attested_keys entries must be public asymmetric JWKs',
          });
      });

      it('rejects private RSA and OKP JWKs in attested_keys', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        for (const alg of ['RS256', 'Ed25519']) {
          const nonce = await getCNonce.call(fixture8);
          const { privateKey } = await generateKeyPair(alg, { extractable: true });
          const privateJwk = await exportJWK(privateKey);
          const attestation = await keyAttestation([privateJwk], { nonce });

          await fixture8.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof attested_keys entries must be public asymmetric JWKs',
            });
        }
      });

      if (SubtleCrypto.supports?.('generateKey', 'ML-DSA-44')) {
        it('rejects attestation proof with a private AKP JWK in attested_keys', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture8);
          const nonce = await getCNonce.call(fixture8);
          const { privateKey } = await generateKeyPair('ML-DSA-44', { extractable: true });
          const privateJwk = await exportJWK(privateKey);
          const attestation = await keyAttestation([privateJwk], { nonce });

          return fixture8.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof attested_keys entries must be public asymmetric JWKs',
            });
        });
      }

      it('rejects attestation proof with a symmetric JWK in attested_keys', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestation = await keyAttestation([{
          kty: 'oct',
          k: Buffer.from('secret').toString('base64url'),
        }], { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof attested_keys entries must be public asymmetric JWKs',
          });
      });

      it('rejects attestation proof with unknown issuer', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          iss: 'https://unknown-provider.example.com',
        });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description: 'attestation proof signature verification failed',
          });
      });

      it('rejects attestation proof type for jwt-only credential configuration', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);
        const nonce = await getCNonce.call(fixture8);
        const attestedKeys = [await exportJWK(fixture8.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description:
              "proof type 'attestation' is not supported for this credential configuration",
          });
      });

      it('rejects non-string attestation value in singular proof', { timeout: 3000 }, async () => {
        const accessToken = await getAccessToken.call(fixture8);

        return fixture8.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proof: {
              proof_type: 'attestation',
              attestation: 123,
            },
          })
          .expect(400)
          .expect({
            error: 'invalid_proof',
            error_description:
              'proof.attestation must be a non-empty string when proof_type is attestation',
          });
      });

      describe('optional claims validation', () => {
        const fixture9 = Object.create(fixture8);

        it('rejects key_storage that is not a non-empty array of strings', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture9);
          const nonce = await getCNonce.call(fixture9);
          const attestedKeys = [await exportJWK(fixture9.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: 'not-an-array',
          });

          return fixture9.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof key_storage must be a non-empty array of non-empty strings',
            });
        });

        it('rejects empty key_storage array', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture9);
          const nonce = await getCNonce.call(fixture9);
          const attestedKeys = [await exportJWK(fixture9.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: [],
          });

          return fixture9.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof key_storage must be a non-empty array of non-empty strings',
            });
        });

        it('rejects user_authentication that is not a non-empty array of strings', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture9);
          const nonce = await getCNonce.call(fixture9);
          const attestedKeys = [await exportJWK(fixture9.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            user_authentication: [123],
          });

          return fixture9.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof user_authentication must be a non-empty array of non-empty strings',
            });
        });

        it('rejects certification that is not a string', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture9);
          const nonce = await getCNonce.call(fixture9);
          const attestedKeys = [await exportJWK(fixture9.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            certification: 123,
          });

          return fixture9.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof certification must be a non-empty string',
            });
        });

        it('rejects certification that is not a URL', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture9);
          const nonce = await getCNonce.call(fixture9);
          const attestedKeys = [await exportJWK(fixture9.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            certification: 'not a URL',
          });

          return fixture9.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof certification must be a URL',
            });
        });

        it('accepts valid optional claims', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture9);
          const nonce = await getCNonce.call(fixture9);
          const attestedKeys = [await exportJWK(fixture9.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_high'],
            user_authentication: ['iso_18045_moderate'],
            certification: 'https://certification.example.com/report',
          });

          return fixture9.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(200)
            .expect((response) => {
              ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
            });
        });
      });

      describe('key_attestations_required enforcement', () => {
        const fixture10 = Object.create(fixture8);

        it('issues credentials when attestation meets key_attestations_required', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture10);
          const nonce = await getCNonce.call(fixture10);
          const attestedKeys = [await exportJWK(fixture10.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_moderate'],
            user_authentication: ['iso_18045_moderate'],
          });

          return fixture10.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation.required',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(200)
            .expect((response) => {
              ((actual) => { assert.ok('credentials' in Object(actual)); assert.ok(Array.isArray(actual.credentials)); assert.equal(actual.credentials.length, 1); })(response.body);
            });
        });

        it('rejects when key_storage is missing but required', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture10);
          const nonce = await getCNonce.call(fixture10);
          const attestedKeys = [await exportJWK(fixture10.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            user_authentication: ['iso_18045_moderate'],
          });

          return fixture10.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation.required',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof key_storage does not meet the credential configuration requirements',
            });
        });

        it('rejects when key_storage values do not match any required value', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture10);
          const nonce = await getCNonce.call(fixture10);
          const attestedKeys = [await exportJWK(fixture10.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_basic'],
            user_authentication: ['iso_18045_moderate'],
          });

          return fixture10.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation.required',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof key_storage does not meet the credential configuration requirements',
            });
        });

        it('rejects when user_authentication is missing but required', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture10);
          const nonce = await getCNonce.call(fixture10);
          const attestedKeys = [await exportJWK(fixture10.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_high'],
          });

          return fixture10.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation.required',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof user_authentication does not meet the credential configuration requirements',
            });
        });

        it('rejects when user_authentication values do not match any required value', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture10);
          const nonce = await getCNonce.call(fixture10);
          const attestedKeys = [await exportJWK(fixture10.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_high'],
            user_authentication: ['iso_18045_basic'],
          });

          return fixture10.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation.required',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(400)
            .expect({
              error: 'invalid_proof',
              error_description: 'attestation proof user_authentication does not meet the credential configuration requirements',
            });
        });

        it('accepts when one of multiple key_storage values matches', { timeout: 3000 }, async () => {
          const accessToken = await getAccessToken.call(fixture10);
          const nonce = await getCNonce.call(fixture10);
          const attestedKeys = [await exportJWK(fixture10.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_basic', 'iso_18045_high'],
            user_authentication: ['iso_18045_moderate'],
          });

          return fixture10.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation.required',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(200);
        });
      });
    });
  });
});
