import { hash, randomUUID } from 'node:crypto';

import { expect } from 'chai';
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

function ath(accessToken) {
  return hash('sha256', accessToken, 'base64url');
}

async function credentialProof(keypair, issuer, {
  aud = issuer,
  nonce,
  typ = 'openid4vci-proof+jwt',
  alg = 'ES256',
  withIat = true,
  key_attestation,
} = {}) {
  const header = {
    alg,
    typ,
    jwk: await exportJWK(keypair.publicKey),
  };

  if (key_attestation !== undefined) {
    header.key_attestation = key_attestation;
  }

  const jwt = new SignJWT({
    aud,
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
  withAttestedKeys = true,
  withExp = false,
  signingKey = attesterKeypair.privateKey,
  key_storage,
  user_authentication,
  certification,
} = {}) {
  const payload = {};
  if (nonce !== undefined) payload.nonce = nonce;
  if (withAttestedKeys) payload.attested_keys = attestedKeys;
  if (key_storage !== undefined) payload.key_storage = key_storage;
  if (user_authentication !== undefined) payload.user_authentication = user_authentication;
  if (certification !== undefined) payload.certification = certification;

  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg, typ })
    .setIssuer(iss);

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
  it('requires jwk cryptographic binding when jwt proofs are supported', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].cryptographic_binding_methods_supported must include 'jwk' when jwt proofs are supported");
  });

  it('requires valid batch credential issuance metadata when configured', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw('features.openid4vci.metadata.batch_credential_issuance.batch_size must be an integer greater than or equal to 2');
  });

  it('rejects credential configuration with unsupported proof type', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported contains unsupported proof type(s): cwt");
  });

  it('rejects credential configuration with unsupported cryptographic binding method', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].cryptographic_binding_methods_supported contains unsupported method(s): cose_key");
  });

  it('rejects credential configuration with credential_response_encryption', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].credential_response_encryption is not supported");
  });

  it('rejects metadata with credential_response_encryption', () => {
    const config = getConfig();

    config.features.openid4vci = {
      enabled: true,
      ack: 'experimental-01',
      nonceSecret: Buffer.alloc(32, 0),
      metadata: {
        credential_response_encryption: {
          alg_values_supported: ['ECDH-ES'],
          enc_values_supported: ['A128GCM'],
          encryption_required: false,
        },
      },
      credentialConfigurationsSupported: {
        valid: {
          format: 'mso_mdoc',
        },
      },
    };

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw('features.openid4vci.metadata.credential_response_encryption is not supported');
  });

  it('rejects key_attestations_required that is not a plain object', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required must be a plain object");
  });

  it('rejects key_attestations_required.key_storage that is not a non-empty array of strings', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required.key_storage must be a non-empty array of non-empty strings");
  });

  it('rejects key_attestations_required.key_storage that is an empty array', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required.key_storage must be a non-empty array of non-empty strings");
  });

  it('rejects key_attestations_required.user_authentication that is not valid', () => {
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

    expect(() => {
      new Provider('http://localhost', config); // eslint-disable-line no-new
    }).to.throw("features.openid4vci.credentialConfigurationsSupported['invalid'].proof_types_supported.attestation.key_attestations_required.user_authentication must be a non-empty array of non-empty strings");
  });
});

describe('features.openid4vci', () => {
  before(bootstrap(import.meta.url));

  it('exposes credential issuer metadata endpoint', function () {
    return this.agent.get('/.well-known/openid-credential-issuer')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('credential_issuer').that.matches(/^http:\/\/127\.0\.0\.1:/);
        expect(response.body).to.have.property('credential_endpoint').that.matches(/\/credential$/);
        expect(response.body).to.have.property('nonce_endpoint').that.matches(/\/challenge$/);
        expect(response.body).to.have.property('test_metadata_member', 'test-value');
        expect(response.body).to.have.property('batch_credential_issuance').that.deep.equals({ batch_size: 2 });
        expect(response.body.credential_configurations_supported).to.have.property('org.iso.18013.5.1.mDL');
        expect(response.body.credential_configurations_supported['org.iso.18013.5.1.mDL']).to.have.property('format', 'mso_mdoc');
        expect(response.body.credential_configurations_supported['org.iso.18013.5.1.mDL'])
          .to.have.property('cryptographic_binding_methods_supported')
          .that.deep.equals(['jwk']);
      });
  });

  describe('authorization_details validations', () => {
    it('rejects openid_credential detail without credential_configuration_id', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        authorization_details: JSON.stringify([
          {
            type: 'openid_credential',
          },
        ]),
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_authorization_details'))
        .expect(auth.validateErrorDescription("'credential_configuration_id' must be a non-empty string"));
    });

    it('rejects openid_credential claims path entries with invalid types', function () {
      const auth = new this.AuthorizationRequest({
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

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_authorization_details'))
        .expect(auth.validateErrorDescription('claims description path entries must be non-empty strings, null, or non-negative integers'));
    });
  });

  describe('credential endpoint', () => {
    before(function () {
      const credentialResource = `${this.provider.issuer}${this.suitePath('/credential')}`;

      return this.login({
        scope: 'mdl_scope',
        resources: {
          [credentialResource]: 'mdl_scope',
        },
      });
    });
    after(function () { return this.logout(); });
    before(async function () {
      this.keypair = await generateKeyPair('ES256', { extractable: true });
      this.thumbprint = await calculateJwkThumbprint(await exportJWK(this.keypair.publicKey));
      this.otherKeypair = await generateKeyPair('ES256', { extractable: true });
    });

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

    it('issues credentials through configured helper', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });

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
          expect(response.body.credentials[0]).to.have.property('credential');
        });
    });

    it('issues c_nonce from challenge endpoint', function () {
      return this.agent.post('/challenge')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('c_nonce').that.is.a('string').and.not.empty;
        });
    });

    it('challenges with Bearer and DPoP when no access token is provided', async function () {
      return this.agent.post('/credential')
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
        .expect('WWW-Authenticate', /algs="ES256"/);
    });

    it('supports sender-constrained DPoP access tokens', async function () {
      const accessToken = await getSenderConstrainedAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });
      const htu = `${this.provider.issuer}${this.suitePath('/credential')}`;

      return this.agent.post('/credential')
        .set('Authorization', `DPoP ${accessToken}`)
        .set('DPoP', await DPoP(this.keypair, htu, 'POST', accessToken))
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

    it('rejects DPoP authorization scheme without DPoP header', async function () {
      const accessToken = await getSenderConstrainedAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
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

    it('rejects Bearer authorization when DPoP header is provided', async function () {
      const accessToken = await getSenderConstrainedAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });
      const htu = `${this.provider.issuer}${this.suitePath('/credential')}`;

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('DPoP', await DPoP(this.keypair, htu, 'POST', accessToken))
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

    it('rejects sender-constrained token when DPoP key does not match jkt', async function () {
      const accessToken = await getSenderConstrainedAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });
      const htu = `${this.provider.issuer}${this.suitePath('/credential')}`;

      return this.agent.post('/credential')
        .set('Authorization', `DPoP ${accessToken}`)
        .set('DPoP', await DPoP(this.otherKeypair, htu, 'POST', accessToken))
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

    it('rejects replayed DPoP proof JWTs', async function () {
      const accessToken = await getSenderConstrainedAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });
      const htu = `${this.provider.issuer}${this.suitePath('/credential')}`;
      const dpop = await DPoP(this.keypair, htu, 'POST', accessToken);

      await this.agent.post('/credential')
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
      this.provider.once('credential.error', spy);
      await this.agent.post('/credential')
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

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.be.instanceOf(InvalidToken);
      expect(spy.args[0][1]).to.have.property(
        'error_detail',
        'DPoP proof JWT Replay detected',
      );
    });

    describe('access token audience', () => {
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

      it('rejects access tokens with a different audience', async function () {
        const accessToken = await getAccessTokenWithAudience.call(this, aliasAudience);

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

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'token audience prevents accessing the credential endpoint');
      });

      describe('with a credentialEndpointExpectedAudience helper', () => {
        before(function () {
          this.orig = i(this.provider).features.openid4vci.credentialEndpointExpectedAudience;
          i(this.provider).features.openid4vci.credentialEndpointExpectedAudience = () => aliasAudience;
        });
        after(function () {
          i(this.provider).features.openid4vci.credentialEndpointExpectedAudience = this.orig;
        });

        it('accepts the audience the helper returns', async function () {
          const accessToken = await getAccessTokenWithAudience.call(this, aliasAudience);
          const proof = await credentialProof(this.keypair, this.provider.issuer, {
            nonce: await getCNonce.call(this),
          });

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

        it('rejects the credential endpoint url the default would have accepted', async function () {
          const accessToken = await getAccessTokenWithAudience.call(this, `${this.provider.issuer}${this.suitePath('/credential')}`);

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

          expect(spy).to.have.property('calledOnce', true);
          expect(spy.args[0][1]).to.have.property('error_detail', 'token audience prevents accessing the credential endpoint');
        });
      });

      describe('with a credentialEndpointExpectedAudience helper returning a non-string', () => {
        before(function () {
          this.orig = i(this.provider).features.openid4vci.credentialEndpointExpectedAudience;
          i(this.provider).features.openid4vci.credentialEndpointExpectedAudience = () => undefined;
        });
        after(function () {
          i(this.provider).features.openid4vci.credentialEndpointExpectedAudience = this.orig;
        });

        it('is a server_error', async function () {
          const accessToken = await getAccessTokenWithAudience.call(this, aliasAudience);

          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          await this.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL',
            })
            .expect(500);

          expect(spy).to.have.property('calledOnce', true);
          expect(spy.args[0][1]).to.have.property('message', 'features.openid4vci.credentialEndpointExpectedAudience must return a string');
        });
      });
    });

    it('returns unknown_credential_configuration for unknown ids', async function () {
      const accessToken = await getAccessToken.call(this);

      return this.agent.post('/credential')
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

    it('supports full authorization code flow with scope for scoped configuration', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'mdl_scope',
      });

      let location;
      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect((response) => {
          ({ location } = response.headers);
        });

      if (/^\/interaction\//.test(location)) {
        await this.agent.post(location)
          .send({ prompt: 'consent' })
          .type('form')
          .expect(303)
          .expect(({ headers }) => {
            ({ location } = headers);
          })
          .expect('location', /\/auth\//);

        await this.agent.get(new URL(location, this.provider.issuer).pathname)
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']));
      } else {
        auth.validatePresence(['code', 'state'])({ headers: { location } });
      }

      const tokenResponse = await this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'authorization_code',
          code: auth.res.code,
          code_verifier: auth.code_verifier,
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200);

      expect(tokenResponse.body).to.not.have.property('authorization_details');

      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${tokenResponse.body.access_token}`)
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

    it('supports full authorization code flow with authorization_details for no-scope configuration', async function () {
      const authorizationDetails = [{
        type: 'openid_credential',
        credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
      }];

      const auth = new this.AuthorizationRequest({
        response_type: 'code',

        authorization_details: JSON.stringify(authorizationDetails),
      });

      let location;
      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect((response) => {
          ({ location } = response.headers);
        })
        .expect('location', new RegExp(`^${this.suitePath('/interaction/')}`));

      await this.agent.post(location)
        .send({ prompt: 'consent' })
        .type('form')
        .expect(303)
        .expect(({ headers }) => {
          ({ location } = headers);
        })
        .expect('location', /\/auth\//);

      await this.agent.get(new URL(location, this.provider.issuer).pathname)
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']));

      const tokenResponse = await this.agent.post('/token')
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

      expect(tokenResponse.body).to.have.property('authorization_details').that.deep.equals([{
        ...authorizationDetails[0],
        credential_identifiers: ['org.iso.18013.5.1.mDL.no_scope-id-1'],
      }]);

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${tokenResponse.body.access_token}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
        });
    });

    it('supports full authorization code flow with credential_identifier', async function () {
      const authorizationDetails = [{
        type: 'openid_credential',
        credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
      }];

      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        authorization_details: JSON.stringify(authorizationDetails),
      });

      let location;
      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect((response) => {
          ({ location } = response.headers);
        })
        .expect('location', new RegExp(`^${this.suitePath('/interaction/')}`));

      await this.agent.post(location)
        .send({ prompt: 'consent' })
        .type('form')
        .expect(303)
        .expect(({ headers }) => {
          ({ location } = headers);
        })
        .expect('location', /\/auth\//);

      await this.agent.get(new URL(location, this.provider.issuer).pathname)
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']));

      const tokenResponse = await this.agent.post('/token')
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

      expect(tokenResponse.body).to.have.property('authorization_details');
      const returnedDetails = tokenResponse.body.authorization_details;
      expect(returnedDetails).to.be.an('array').with.lengthOf(1);
      expect(returnedDetails[0]).to.have.property('credential_identifiers')
        .that.is.an('array').and.not.empty;

      const [credentialIdentifier] = returnedDetails[0].credential_identifiers;

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${tokenResponse.body.access_token}`)
        .send({
          credential_identifier: credentialIdentifier,
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
          const issued = JSON.parse(response.body.credentials[0].credential);
          expect(issued).to.have.property('credential_identifier', credentialIdentifier);
        });
    });

    it('denies no-scope credential configuration without matching authorization_details', async function () {
      const accessToken = await getAccessToken.call(this);

      return this.agent.post('/credential')
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

    it('allows no-scope credential configuration with matching authorization_details', async function () {
      const accessToken = await getRarAccessToken.call(this, 'org.iso.18013.5.1.mDL.no_scope');

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL.no_scope',
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
        });
    });

    it('issues credentials using credential_identifier from authorization_details', async function () {
      const accessToken = await getRarAccessTokenWithIdentifiers.call(
        this,
        'org.iso.18013.5.1.mDL.no_scope',
        ['CivilEngineeringDegree-2023'],
      );

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_identifier: 'CivilEngineeringDegree-2023',
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
          const issued = JSON.parse(response.body.credentials[0].credential);
          expect(issued).to.have.property('format', 'org.iso.18013.5.1.mDL.no_scope');
          expect(issued).to.have.property('credential_identifier', 'CivilEngineeringDegree-2023');
        });
    });

    it('issues credentials using credential_identifier with proofs', async function () {
      const accessToken = await getRarAccessTokenWithIdentifiers.call(
        this,
        'org.iso.18013.5.1.mDL',
        ['mDL-instance-1'],
      );
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_identifier: 'mDL-instance-1',
          proofs: {
            jwt: [proof],
          },
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
          const issued = JSON.parse(response.body.credentials[0].credential);
          expect(issued).to.have.property('format', 'org.iso.18013.5.1.mDL');
          expect(issued).to.have.property('credential_identifier', 'mDL-instance-1');
        });
    });

    it('returns unknown_credential_identifier when credential_identifier is not in access token', async function () {
      const accessToken = await getRarAccessToken.call(this, 'org.iso.18013.5.1.mDL.no_scope');

      return this.agent.post('/credential')
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

    it('returns unknown_credential_identifier when access token has no authorization_details', async function () {
      const accessToken = await getAccessToken.call(this);

      return this.agent.post('/credential')
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

    it('returns invalid_proof when proofs are required but missing', async function () {
      const accessToken = await getAccessToken.call(this);

      return this.agent.post('/credential')
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

    it('returns invalid_proof when JWT proof nonce is missing', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer);

      return this.agent.post('/credential')
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

    it('returns invalid_proof when JWT proof iat is missing', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
        withIat: false,
      });

      return this.agent.post('/credential')
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

    it('returns invalid_nonce when JWT proof nonce is present but invalid', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: 'invalid-nonce-value',
      });

      return this.agent.post('/credential')
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

    it('accepts a single proof object', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
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
          expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
        });
    });

    it('accepts multiple jwt proofs up to configured batch_size', async function () {
      const accessToken = await getAccessToken.call(this);
      const nonce = await getCNonce.call(this);
      const proofOne = await credentialProof(this.keypair, this.provider.issuer, { nonce });
      const proofTwo = await credentialProof(this.otherKeypair, this.provider.issuer, { nonce });

      return this.agent.post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'org.iso.18013.5.1.mDL',
          proofs: {
            jwt: [proofOne, proofTwo],
          },
        })
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
        });
    });

    it('returns invalid_proof when jwt proof batch exceeds configured batch_size', async function () {
      const accessToken = await getAccessToken.call(this);
      const nonce = await getCNonce.call(this);
      const proofOne = await credentialProof(this.keypair, this.provider.issuer, { nonce });
      const proofTwo = await credentialProof(this.otherKeypair, this.provider.issuer, { nonce });
      const thirdKeypair = await generateKeyPair('ES256', { extractable: true });
      const proofThree = await credentialProof(thirdKeypair, this.provider.issuer, { nonce });

      return this.agent.post('/credential')
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

    it('rejects using proof and proofs together', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
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

    it('returns invalid_proof for multiple proof types', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
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

    it('returns invalid_proof for invalid JWT proof typ', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        nonce: await getCNonce.call(this),
        typ: 'JWT',
      });

      return this.agent.post('/credential')
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

    it('returns invalid_proof for JWT proof with aud mismatch', async function () {
      const accessToken = await getAccessToken.call(this);
      const proof = await credentialProof(this.keypair, this.provider.issuer, {
        aud: 'https://attacker.example.com',
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
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

    it('returns invalid_proof for JWT proof alg not supported by credential configuration', async function () {
      const accessToken = await getAccessToken.call(this);
      const p384 = await generateKeyPair('ES384', { extractable: true });
      const proof = await credentialProof(p384, this.provider.issuer, {
        alg: 'ES384',
        nonce: await getCNonce.call(this),
      });

      return this.agent.post('/credential')
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
      it('issues credentials with a valid key_attestation in jwt proof header', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, { withExp: true });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

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
            const issued = JSON.parse(response.body.credentials[0].credential);
            expect(issued).to.have.property('proof_type', 'jwt');
            expect(issued).to.have.property('attested_keys_count', 1);
          });
      });

      it('rejects key_attestation without exp', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys);
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('rejects key_attestation when jwt proof jwk is not among attested keys', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const otherKeys = [await exportJWK(this.otherKeypair.publicKey)];
        const ka = await keyAttestation(otherKeys, { withExp: true });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('rejects key_attestation with invalid signature', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const wrongKey = await generateKeyPair('ES256', { extractable: true });
        const ka = await keyAttestation(attestedKeys, {
          withExp: true, signingKey: wrongKey.privateKey,
        });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('rejects key_attestation with wrong typ', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, { withExp: true, typ: 'JWT' });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('rejects key_attestation with missing iat', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, { withExp: true, withIat: false });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('rejects key_attestation with unknown issuer', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          iss: 'https://unknown-provider.example.com',
        });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('rejects when key_attestations_required but no key_attestation header', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const proof = await credentialProof(this.keypair, this.provider.issuer, { nonce });

        return this.agent.post('/credential')
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

      it('issues credentials when key_attestations_required and attestation meets requirements', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          key_storage: ['iso_18045_moderate'],
          user_authentication: ['iso_18045_moderate'],
        });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.jwt.attestation_required',
            proofs: {
              jwt: [proof],
            },
          })
          .expect(200)
          .expect((response) => {
            expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
          });
      });

      it('rejects when key_attestation key_storage does not meet requirements', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          key_storage: ['iso_18045_basic'],
          user_authentication: ['iso_18045_moderate'],
        });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('rejects when key_attestation user_authentication is missing but required', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const ka = await keyAttestation(attestedKeys, {
          withExp: true,
          key_storage: ['iso_18045_high'],
        });
        const proof = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
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

      it('requires all batch jwt proofs to reference the same key_attestation', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [
          await exportJWK(this.keypair.publicKey),
          await exportJWK(this.otherKeypair.publicKey),
        ];
        const ka1 = await keyAttestation(attestedKeys, { withExp: true });
        const ka2 = await keyAttestation(attestedKeys, { withExp: true });
        const proof1 = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka1,
        });
        const proof2 = await credentialProof(this.otherKeypair, this.provider.issuer, {
          nonce,
          key_attestation: ka2,
        });

        return this.agent.post('/credential')
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

      it('accepts batch jwt proofs with the same key_attestation', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [
          await exportJWK(this.keypair.publicKey),
          await exportJWK(this.otherKeypair.publicKey),
        ];
        const ka = await keyAttestation(attestedKeys, { withExp: true });
        const proof1 = await credentialProof(this.keypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });
        const proof2 = await credentialProof(this.otherKeypair, this.provider.issuer, {
          nonce,
          key_attestation: ka,
        });

        return this.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL',
            proofs: {
              jwt: [proof1, proof2],
            },
          })
          .expect(200)
          .expect((response) => {
            expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
            const issued = JSON.parse(response.body.credentials[0].credential);
            expect(issued).to.have.property('attested_keys_count', 2);
          });
      });
    });

    describe('attestation proof type', () => {
      it('issues credentials with a valid attestation proof', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return this.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(200)
          .expect((response) => {
            expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
            const issued = JSON.parse(response.body.credentials[0].credential);
            expect(issued).to.have.property('proof_type', 'attestation');
            expect(issued).to.have.property('attested_keys_count', 1);
          });
      });

      it('issues credentials with multiple attested keys', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [
          await exportJWK(this.keypair.publicKey),
          await exportJWK(this.otherKeypair.publicKey),
        ];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return this.agent.post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
            proofs: {
              attestation: [attestation],
            },
          })
          .expect(200)
          .expect((response) => {
            expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
            const issued = JSON.parse(response.body.credentials[0].credential);
            expect(issued).to.have.property('attested_keys_count', 2);
          });
      });

      it('accepts a single attestation proof object', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return this.agent.post('/credential')
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
            expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
          });
      });

      it('rejects attestation proof with missing nonce', async function () {
        const accessToken = await getAccessToken.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys);

        return this.agent.post('/credential')
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

      it('rejects attestation proof with invalid nonce', async function () {
        const accessToken = await getAccessToken.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce: 'invalid-nonce-value',
        });

        return this.agent.post('/credential')
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

      it('rejects attestation proof with missing iat', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          withIat: false,
        });

        return this.agent.post('/credential')
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

      it('rejects attestation proof with wrong typ', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          typ: 'JWT',
        });

        return this.agent.post('/credential')
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

      it('rejects attestation proof with invalid signature', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const wrongKey = await generateKeyPair('ES256', { extractable: true });
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          signingKey: wrongKey.privateKey,
        });

        return this.agent.post('/credential')
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

      it('rejects attestation proof with unsupported alg', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const p384 = await generateKeyPair('ES384', { extractable: true });
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          alg: 'ES384',
          signingKey: p384.privateKey,
        });

        return this.agent.post('/credential')
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

      it('rejects multiple attestation JWTs in proofs', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation1 = await keyAttestation(attestedKeys, { nonce });
        const attestation2 = await keyAttestation(attestedKeys, { nonce });

        return this.agent.post('/credential')
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

      it('rejects attestation proof with empty attested_keys', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestation = await keyAttestation([], { nonce });

        return this.agent.post('/credential')
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

      it('rejects attestation proof with non-object attested_keys entries', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestation = await keyAttestation(['not-an-object'], { nonce });

        return this.agent.post('/credential')
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

      it('rejects attestation proof with unknown issuer', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, {
          nonce,
          iss: 'https://unknown-provider.example.com',
        });

        return this.agent.post('/credential')
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

      it('rejects attestation proof type for jwt-only credential configuration', async function () {
        const accessToken = await getAccessToken.call(this);
        const nonce = await getCNonce.call(this);
        const attestedKeys = [await exportJWK(this.keypair.publicKey)];
        const attestation = await keyAttestation(attestedKeys, { nonce });

        return this.agent.post('/credential')
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

      it('rejects non-string attestation value in singular proof', async function () {
        const accessToken = await getAccessToken.call(this);

        return this.agent.post('/credential')
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
        it('rejects key_storage that is not a non-empty array of strings', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: 'not-an-array',
          });

          return this.agent.post('/credential')
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

        it('rejects empty key_storage array', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: [],
          });

          return this.agent.post('/credential')
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

        it('rejects user_authentication that is not a non-empty array of strings', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            user_authentication: [123],
          });

          return this.agent.post('/credential')
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

        it('rejects certification that is not a string', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            certification: 123,
          });

          return this.agent.post('/credential')
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

        it('accepts valid optional claims', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_high'],
            user_authentication: ['iso_18045_moderate'],
            certification: 'https://certification.example.com/report',
          });

          return this.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(200)
            .expect((response) => {
              expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
            });
        });
      });

      describe('key_attestations_required enforcement', () => {
        it('issues credentials when attestation meets key_attestations_required', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_moderate'],
            user_authentication: ['iso_18045_moderate'],
          });

          return this.agent.post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'org.iso.18013.5.1.mDL.attestation.required',
              proofs: {
                attestation: [attestation],
              },
            })
            .expect(200)
            .expect((response) => {
              expect(response.body).to.have.property('credentials').that.is.an('array').with.lengthOf(1);
            });
        });

        it('rejects when key_storage is missing but required', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            user_authentication: ['iso_18045_moderate'],
          });

          return this.agent.post('/credential')
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

        it('rejects when key_storage values do not match any required value', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_basic'],
            user_authentication: ['iso_18045_moderate'],
          });

          return this.agent.post('/credential')
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

        it('rejects when user_authentication is missing but required', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_high'],
          });

          return this.agent.post('/credential')
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

        it('rejects when user_authentication values do not match any required value', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_high'],
            user_authentication: ['iso_18045_basic'],
          });

          return this.agent.post('/credential')
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

        it('accepts when one of multiple key_storage values matches', async function () {
          const accessToken = await getAccessToken.call(this);
          const nonce = await getCNonce.call(this);
          const attestedKeys = [await exportJWK(this.keypair.publicKey)];
          const attestation = await keyAttestation(attestedKeys, {
            nonce,
            key_storage: ['iso_18045_basic', 'iso_18045_high'],
            user_authentication: ['iso_18045_moderate'],
          });

          return this.agent.post('/credential')
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
