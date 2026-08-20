import {
  EmbeddedJWK, jwtVerify, decodeProtectedHeader, decodeJwt, calculateJwkThumbprint,
} from 'jose';

import noCache from '../shared/no_cache.js';
import { json as parseBody } from '../shared/selective_body.js';
import paramsMiddleware from '../shared/assemble_params.js';
import rejectDupes from '../shared/reject_dupes.js';
import getSetWWWAuthenticateHeader from '../shared/set_www_authenticate_header.js';
import getValidateJsonBody from '../shared/validate_json_body.js';
import instance from '../helpers/weak_cache.js';
import {
  getValidateAccessToken,
  loadAccessTokenAccount,
  loadAccessTokenClient,
  loadAccessTokenGrant,
} from '../shared/access_token.js';
import {
  InvalidToken,
  InvalidCredentialRequest,
  UnknownCredentialConfiguration,
  UnknownCredentialIdentifier,
  InvalidNonce,
  InvalidProof,
  CredentialRequestDenied,
} from '../helpers/errors.js';

const PARAM_LIST = new Set([
  'credential_identifier',
  'credential_configuration_id',
  'proof',
  'proofs',
]);

function assertSingleProofType(proofs) {
  // OpenID4VCI 1.0, proof container semantics (`proofs` carries a single proof type per request):
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
  const types = Object.keys(proofs);
  if (types.length !== 1) {
    throw new InvalidProof('exactly one proof type must be provided in proofs');
  }

  const [type] = types;
  const values = proofs[type];
  if (!Array.isArray(values) || values.length === 0) {
    throw new InvalidProof(`proofs.${type} must be a non-empty array`);
  }

  return { type, values };
}

async function verifyKeyAttestation(
  attestationJwt,
  openid4vci,
  {
    errorPrefix, supportedAlgs, requiredClaims, keyAttestationsRequired,
  },
  ctx,
) {
  // OpenID4VCI 1.0, Key Attestation in JWT format:
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestation-in-jwt-form

  let header;
  let claims;
  try {
    header = decodeProtectedHeader(attestationJwt);
    claims = decodeJwt(attestationJwt);
  } catch (cause) {
    throw new InvalidProof(`${errorPrefix} must be a valid JWT`, { cause });
  }

  if (typeof claims.iss !== 'string' || !claims.iss.length) {
    throw new InvalidProof(`${errorPrefix} iss must be a non-empty string`);
  }

  const key = await openid4vci.getKeyAttestationSignaturePublicKey(
    ctx,
    claims.iss,
    header,
    ctx.oidc.client,
  ).catch((cause) => {
    throw new InvalidProof(`${errorPrefix} signature verification failed`, { cause });
  });

  let payload;
  try {
    ({ payload } = await jwtVerify(attestationJwt, key, {
      algorithms: supportedAlgs,
      typ: 'key-attestation+jwt',
      requiredClaims,
    }));
  } catch (cause) {
    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'typ') {
      throw new InvalidProof(`${errorPrefix} typ must be key-attestation+jwt`, { cause });
    }

    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'iat') {
      throw new InvalidProof(`${errorPrefix} iat must be present`, { cause });
    }

    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'exp') {
      throw new InvalidProof(`${errorPrefix} exp must be present`, { cause });
    }

    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'attested_keys') {
      throw new InvalidProof(`${errorPrefix} attested_keys must be present`, { cause });
    }

    if (cause?.code === 'ERR_JWT_EXPIRED') {
      throw new InvalidProof(`${errorPrefix} has expired`, { cause });
    }

    if (supportedAlgs && cause?.code === 'ERR_JOSE_ALG_NOT_ALLOWED') {
      throw new InvalidProof(
        `${errorPrefix} alg is not supported for this credential configuration`,
        { cause },
      );
    }

    throw new InvalidProof(`${errorPrefix} signature verification failed`, { cause });
  }

  if (!Array.isArray(payload.attested_keys) || payload.attested_keys.length === 0) {
    throw new InvalidProof(`${errorPrefix} attested_keys must be a non-empty array`);
  }

  for (const jwk of payload.attested_keys) {
    if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) {
      throw new InvalidProof(`${errorPrefix} attested_keys entries must be JWK objects`);
    }
  }

  // OpenID4VCI 1.0, Appendix D.1 - structural validation of optional Key Attestation claims:
  if (payload.key_storage !== undefined) {
    if (
      !Array.isArray(payload.key_storage)
      || payload.key_storage.length === 0
      || !payload.key_storage.every((v) => typeof v === 'string' && v.length > 0)
    ) {
      throw new InvalidProof(`${errorPrefix} key_storage must be a non-empty array of non-empty strings`);
    }
  }

  if (payload.user_authentication !== undefined) {
    if (
      !Array.isArray(payload.user_authentication)
      || payload.user_authentication.length === 0
      || !payload.user_authentication.every((v) => typeof v === 'string' && v.length > 0)
    ) {
      throw new InvalidProof(`${errorPrefix} user_authentication must be a non-empty array of non-empty strings`);
    }
  }

  if (payload.certification !== undefined) {
    if (typeof payload.certification !== 'string' || payload.certification.length === 0) {
      throw new InvalidProof(`${errorPrefix} certification must be a non-empty string`);
    }
  }

  // OpenID4VCI 1.0, Section 12.2.4 - key_attestations_required enforcement:
  if (keyAttestationsRequired) {
    if (Array.isArray(keyAttestationsRequired.key_storage)) {
      if (
        !Array.isArray(payload.key_storage)
        || !payload.key_storage.some((v) => keyAttestationsRequired.key_storage.includes(v))
      ) {
        throw new InvalidProof(`${errorPrefix} key_storage does not meet the credential configuration requirements`);
      }
    }

    if (Array.isArray(keyAttestationsRequired.user_authentication)) {
      if (
        !Array.isArray(payload.user_authentication)
        || !payload.user_authentication.some(
          (v) => keyAttestationsRequired.user_authentication.includes(v),
        )
      ) {
        throw new InvalidProof(`${errorPrefix} user_authentication does not meet the credential configuration requirements`);
      }
    }
  }

  return {
    jwt: attestationJwt,
    attestedKeys: payload.attested_keys,
    payload,
  };
}

function keyAttestationParams(proofType, credentialConfiguration) {
  const config = credentialConfiguration.proof_types_supported?.[proofType];
  const configuredAlgs = config?.proof_signing_alg_values_supported;

  return {
    supportedAlgs: Array.isArray(configuredAlgs) && configuredAlgs.length
      ? [...configuredAlgs]
      : undefined,
    keyAttestationsRequired: config?.key_attestations_required,
  };
}

async function verifyKeyAttestationHeader(
  attestationJwt,
  proofJwk,
  openid4vci,
  credentialConfiguration,
  ctx,
) {
  // OpenID4VCI 1.0, Appendix F.2 - key_attestation JOSE header in JWT proof type:
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type
  // When used with the JWT proof type, the Key Attestation JWT MUST contain exp.
  const result = await verifyKeyAttestation(
    attestationJwt,
    openid4vci,
    {
      errorPrefix: 'jwt proof key_attestation',
      requiredClaims: ['iat', 'exp', 'attested_keys'],
      ...keyAttestationParams('jwt', credentialConfiguration),
    },
    ctx,
  );

  // Verify the JWT proof's embedded JWK is among the attested keys
  const proofThumbprint = await calculateJwkThumbprint(proofJwk);
  const attestedThumbprints = await Promise.all(
    result.attestedKeys.map((jwk) => calculateJwkThumbprint(jwk)),
  );

  if (!attestedThumbprints.includes(proofThumbprint)) {
    throw new InvalidProof(
      'jwt proof jwk is not among the attested keys in key_attestation',
    );
  }

  return result;
}

async function verifyJwtProof(proof, issuer, supportedAlgs, cNonceChallenges) {
  // OpenID4VCI 1.0, JWT proof type processing:
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type
  // OpenID4VCI 1.0, generic proof processing at the credential endpoint:
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint
  let payload;
  try {
    ({ payload } = await jwtVerify(proof, EmbeddedJWK, {
      algorithms: supportedAlgs ? [...supportedAlgs] : undefined,
      audience: issuer,
      typ: 'openid4vci-proof+jwt',
      requiredClaims: ['iat', 'nonce'],
    }));
  } catch (cause) {
    if (cause?.code === 'ERR_JWS_INVALID') {
      throw new InvalidProof('jwt proof must be a compact JWS', { cause });
    }

    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'typ') {
      throw new InvalidProof('jwt proof typ must be openid4vci-proof+jwt', { cause });
    }

    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'aud') {
      throw new InvalidProof('jwt proof aud must equal credential issuer identifier', { cause });
    }

    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'iat') {
      throw new InvalidProof('jwt proof iat must be present', { cause });
    }

    if (cause?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && cause?.claim === 'nonce') {
      throw new InvalidProof('jwt proof nonce must be present', { cause });
    }

    if (supportedAlgs && cause?.code === 'ERR_JOSE_ALG_NOT_ALLOWED') {
      throw new InvalidProof(
        'jwt proof alg is not supported for this credential configuration',
        { cause },
      );
    }

    throw new InvalidProof('jwt proof signature verification failed', { cause });
  }

  if (typeof payload.nonce !== 'string' || !payload.nonce.length) {
    throw new InvalidProof('jwt proof nonce must be a non-empty string');
  }

  if (!cNonceChallenges.checkChallenge(payload.nonce)) {
    // OpenID4VCI 1.0, Section 8.3.1.2 - `invalid_nonce` is distinct from `invalid_proof`:
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-errors
    throw new InvalidNonce('jwt proof nonce is invalid, retrieve a new c_nonce from the nonce endpoint');
  }

  // Return the header for key_attestation processing
  return decodeProtectedHeader(proof);
}

async function verifyAttestationProof(
  attestationJwt,
  openid4vci,
  credentialConfiguration,
  cNonceChallenges,
  ctx,
) {
  // OpenID4VCI 1.0, Appendix F.3 - attestation proof type:
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-attestation-proof-type
  const result = await verifyKeyAttestation(
    attestationJwt,
    openid4vci,
    {
      errorPrefix: 'attestation proof',
      requiredClaims: ['iat', 'attested_keys'],
      ...keyAttestationParams('attestation', credentialConfiguration),
    },
    ctx,
  );

  if (typeof result.payload.nonce !== 'string' || !result.payload.nonce.length) {
    throw new InvalidProof(
      'attestation proof nonce must be present',
    );
  }

  if (!cNonceChallenges.checkChallenge(result.payload.nonce)) {
    throw new InvalidNonce(
      'attestation proof nonce is invalid, retrieve a new c_nonce from the nonce endpoint',
    );
  }

  return result;
}

function normalizeProofs(body) {
  // OpenID4VCI 1.0, requests can carry either `proof` or `proofs`; deployment forbids mixing both:
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
  const hasProof = body.proof !== undefined;
  const hasProofs = body.proofs !== undefined;

  if (hasProof && hasProofs) {
    throw new InvalidCredentialRequest('proof and proofs cannot be used together');
  }

  if (!hasProof) {
    return body.proofs;
  }

  const { proof } = body;

  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    throw new InvalidProof('proof must be a JSON object');
  }

  if (typeof proof.proof_type !== 'string' || !proof.proof_type.length) {
    throw new InvalidProof('proof.proof_type must be a non-empty string');
  }

  if (proof.proof_type === 'jwt') {
    if (typeof proof.jwt !== 'string' || !proof.jwt.length) {
      throw new InvalidProof('proof.jwt must be a non-empty string when proof_type is jwt');
    }

    return {
      jwt: [proof.jwt],
    };
  }

  if (proof.proof_type === 'attestation') {
    if (typeof proof.attestation !== 'string' || !proof.attestation.length) {
      throw new InvalidProof(
        'proof.attestation must be a non-empty string when proof_type is attestation',
      );
    }

    return {
      attestation: [proof.attestation],
    };
  }

  throw new InvalidProof(`proof type '${proof.proof_type}' is not supported by this deployment`);
}

function assertProofs(proofs, credentialConfiguration) {
  // OpenID4VCI 1.0, credential configuration may mandate proof material:
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint
  if (credentialConfiguration.proof_types_supported !== undefined && proofs === undefined) {
    throw new InvalidProof('proofs are required for this credential configuration');
  }

  if (proofs !== undefined && (proofs === null || typeof proofs !== 'object' || Array.isArray(proofs))) {
    throw new InvalidProof('proofs must be a JSON object');
  }
}

function batchSize(openid4vci) {
  const configured = openid4vci?.metadata?.batch_credential_issuance?.batch_size;

  if (!Number.isSafeInteger(configured) || configured < 2) {
    return undefined;
  }

  return configured;
}

const validateAccessToken = getValidateAccessToken();
const validateBody = getValidateJsonBody(
  InvalidCredentialRequest,
  'credential request body must be a JSON object',
);

export default [
  noCache,
  getSetWWWAuthenticateHeader({ includeScope: false }),

  parseBody,
  validateBody,
  paramsMiddleware.bind(undefined, PARAM_LIST),
  rejectDupes.bind(undefined, {}),

  validateAccessToken,

  async function validateAudience(ctx, next) {
    const { openid4vci } = instance(ctx.oidc.provider).configuration.features;
    const expected = await openid4vci.credentialEndpointExpectedAudience(ctx);

    if (typeof expected !== 'string' || !expected) {
      throw new Error('features.openid4vci.credentialEndpointExpectedAudience must return a string');
    }

    if (ctx.oidc.accessToken.aud !== expected) {
      throw new InvalidToken('token audience prevents accessing the credential endpoint');
    }

    return next();
  },

  loadAccessTokenClient,
  loadAccessTokenAccount,
  loadAccessTokenGrant,

  async function issueCredential(ctx) {
    const { openid4vci } = instance(ctx.oidc.provider).configuration.features;
    const { CNonceChallenges } = instance(ctx.oidc.provider);
    const { body } = ctx.oidc;

    const hasCredentialIdentifier = body.credential_identifier !== undefined;
    const hasCredentialConfigurationId = body.credential_configuration_id !== undefined;

    if (hasCredentialIdentifier === hasCredentialConfigurationId) {
      throw new InvalidCredentialRequest(
        'exactly one of credential_identifier or credential_configuration_id must be provided',
      );
    }

    const { credentialConfigurationsSupported } = openid4vci;

    let credentialConfigurationId;
    let credentialConfiguration;
    let credentialIdentifier;

    if (hasCredentialIdentifier) {
      // OpenID4VCI 1.0, credential_identifier resolution against token authorization_details:
      // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
      credentialIdentifier = body.credential_identifier;
      if (typeof credentialIdentifier !== 'string' || !credentialIdentifier.length) {
        throw new InvalidCredentialRequest('credential_identifier must be a non-empty string');
      }

      let matchingDetail;
      if (Array.isArray(ctx.oidc.accessToken.rar)) {
        matchingDetail = ctx.oidc.accessToken.rar.find((detail) => (
          detail?.type === 'openid_credential'
          && Array.isArray(detail?.credential_identifiers)
          && detail.credential_identifiers.includes(credentialIdentifier)
        ));
      }

      if (!matchingDetail) {
        throw new UnknownCredentialIdentifier('credential_identifier not found in the access token authorization details');
      }

      credentialConfigurationId = matchingDetail.credential_configuration_id;
      credentialConfiguration = credentialConfigurationsSupported[credentialConfigurationId];
      if (!credentialConfiguration) {
        throw new UnknownCredentialConfiguration('credential configuration referenced by credential_identifier is unknown');
      }
    } else {
      credentialConfigurationId = body.credential_configuration_id;
      if (typeof credentialConfigurationId !== 'string' || !credentialConfigurationId.length) {
        throw new InvalidCredentialRequest('credential_configuration_id must be a non-empty string');
      }

      credentialConfiguration = credentialConfigurationsSupported[credentialConfigurationId];
      if (!credentialConfiguration) {
        throw new UnknownCredentialConfiguration('requested credential_configuration_id is unknown');
      }
    }

    const policyAllowed = await openid4vci.credentialConfigurationPolicy(ctx, {
      credentialConfigurationId,
      credentialConfiguration,
      credentialIdentifier,
      client: ctx.oidc.client,
      account: ctx.oidc.account,
      grant: ctx.oidc.grant,
      accessToken: ctx.oidc.accessToken,
    });

    if (typeof policyAllowed !== 'boolean') {
      throw new Error('features.openid4vci.credentialConfigurationPolicy must return a boolean');
    }

    if (!policyAllowed) {
      throw new CredentialRequestDenied(
        'access token does not authorize issuance for requested credential configuration',
      );
    }

    const proofs = normalizeProofs(body);

    assertProofs(proofs, credentialConfiguration);

    // OpenID4VCI 1.0, authorization enforcement:
    // When credential_identifier is used, the access token's authorization_details already
    // proved authorization during the identifier lookup above.
    // When credential_configuration_id is used, check scope or RAR entitlement.
    if (!hasCredentialIdentifier) {
      if (
        credentialConfiguration.scope
        && !ctx.oidc.accessToken.scopes.has(credentialConfiguration.scope)
      ) {
        throw new CredentialRequestDenied(
          'access token does not authorize issuance for requested credential configuration',
        );
      }

      if (!credentialConfiguration.scope) {
        // OpenID4VCI authorization details type (`openid_credential`) entitlement enforcement.
        // OpenID4VCI 1.0:
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-authorization-det
        // RAR base model (authorization_details as structured grant data):
        // https://www.rfc-editor.org/rfc/rfc9396.html#section-2
        const authorized = (
          Array.isArray(ctx.oidc.accessToken.rar)
          && ctx.oidc.accessToken.rar.some((detail) => (
            detail?.type === 'openid_credential'
            && detail?.credential_configuration_id === credentialConfigurationId
          ))
        );

        if (!authorized) {
          throw new CredentialRequestDenied(
            'access token does not authorize issuance for requested credential configuration',
          );
        }
      }
    }

    if (proofs !== undefined) {
      const { type, values } = assertSingleProofType(proofs);

      if (
        credentialConfiguration.proof_types_supported !== undefined
        && !Object.hasOwn(credentialConfiguration.proof_types_supported, type)
      ) {
        throw new InvalidProof(
          `proof type '${type}' is not supported for this credential configuration`,
        );
      }

      if (type === 'jwt') {
        const maxBatchSize = batchSize(openid4vci);

        if (values.length > 1) {
          if (!maxBatchSize) {
            throw new InvalidProof('multiple jwt proofs are not supported when batch issuance is disabled');
          }

          if (values.length > maxBatchSize) {
            throw new InvalidProof(`jwt proof batch exceeds configured batch_size (${maxBatchSize})`);
          }
        }

        const configuredAlgs = (
          credentialConfiguration.proof_types_supported?.jwt?.proof_signing_alg_values_supported
        );
        const supportedAlgs = Array.isArray(configuredAlgs) && configuredAlgs.length
          ? new Set(configuredAlgs)
          : undefined;

        let keyAttestationResult;
        for (const proof of values) {
          const header = await verifyJwtProof(
            proof,
            ctx.oidc.issuer,
            supportedAlgs,
            CNonceChallenges,
          );

          // OpenID4VCI 1.0, Appendix F.2 - key_attestation JOSE header parameter:
          if (header.key_attestation !== undefined) {
            if (typeof header.key_attestation !== 'string' || !header.key_attestation.length) {
              throw new InvalidProof('jwt proof key_attestation header must be a non-empty string');
            }

            const result = await verifyKeyAttestationHeader(
              header.key_attestation,
              header.jwk,
              openid4vci,
              credentialConfiguration,
              ctx,
            );

            if (keyAttestationResult) {
              // All JWT proofs in a batch must carry the same Key Attestation JWT
              if (keyAttestationResult.jwt !== result.jwt) {
                throw new InvalidProof('all jwt proofs in a batch must reference the same key_attestation');
              }
            } else {
              keyAttestationResult = result;
            }
          }
        }

        // key_attestations_required enforcement - when configured, key_attestation must be present
        const jwtKeyAttestationsRequired = (
          credentialConfiguration.proof_types_supported?.jwt?.key_attestations_required
        );
        if (jwtKeyAttestationsRequired && !keyAttestationResult) {
          throw new InvalidProof(
            'jwt proof must include a key_attestation header when key attestations are required',
          );
        }

        if (keyAttestationResult) {
          proofs.key_attestation = keyAttestationResult;
        }
      } else if (type === 'attestation') {
        // OpenID4VCI 1.0, Appendix F.3 - attestation proof type:
        // proofs.attestation must contain exactly one JWT
        if (values.length !== 1) {
          throw new InvalidProof(
            'proofs.attestation must contain exactly one key attestation JWT',
          );
        }

        const [attestationJwt] = values;
        if (typeof attestationJwt !== 'string' || !attestationJwt.length) {
          throw new InvalidProof(
            'attestation proof must be a non-empty string',
          );
        }

        const result = await verifyAttestationProof(
          attestationJwt,
          openid4vci,
          credentialConfiguration,
          CNonceChallenges,
          ctx,
        );

        // Replace raw proofs with pre-parsed structured data for issueCredential
        proofs.attestation = result;
      } else {
        throw new InvalidProof(`proof type '${type}' is not supported by this deployment`);
      }
    }

    const out = await openid4vci.issueCredential(ctx, {
      credentialConfigurationId,
      credentialConfiguration,
      credentialIdentifier,
      body,
      proofs,
      client: ctx.oidc.client,
      account: ctx.oidc.account,
      grant: ctx.oidc.grant,
      accessToken: ctx.oidc.accessToken,
    });

    if (!out || typeof out !== 'object' || Array.isArray(out)) {
      throw new Error('features.openid4vci.issueCredential must return an object');
    }

    if (!Array.isArray(out.credentials) || !out.credentials.length) {
      throw new Error('features.openid4vci.issueCredential must return a non-empty credentials array');
    }

    ctx.body = {
      credentials: out.credentials,
      notification_id: out.notification_id,
    };
  },
];
