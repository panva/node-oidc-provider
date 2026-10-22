import * as jose from 'jose';

import {
  InvalidClientAuth, InvalidClientAttestation, InvalidDpopProof, UseAttestationChallenge, UseDpopNonce,
} from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import { CHALLENGE_OK_WINDOW } from '../helpers/challenge.js';
import epochTime from '../helpers/epoch_time.js';
import validateDpop, { checkDpopReplay, getDpopJwt } from '../helpers/validate_dpop.js';

function invalid(ErrorClass, options) {
  if (ErrorClass === InvalidClientAuth) {
    return new ErrorClass(options);
  }

  return new ErrorClass(undefined, options);
}

export async function validateClientAttestationJwtAndPop(ctx, { signal = false } = {}) {
  const {
    configuration: {
      clockTolerance,
      features: { attestClientAuth, dPoP: dPoPConfig },
      attestSigningAlgValues,
    },
    AttestChallenges,
    DPoPNonces,
  } = instance(ctx.oidc.provider);

  const ErrorClass = signal ? InvalidClientAttestation : InvalidClientAuth;

  const attestation = ctx.get('oauth-client-attestation');
  if (!attestation) {
    throw invalid(ErrorClass, 'oauth-client-attestation missing');
  }

  let verifiedAttestation;
  try {
    verifiedAttestation = await jose.jwtVerify(
      attestation,
      async (header) => {
        const payload = jose.decodeJwt(attestation);
        const key = await attestClientAuth.getAttestationSignaturePublicKey(
          ctx,
          header,
          payload,
          ctx.oidc.client,
        );
        return key;
      },
      {
        algorithms: attestSigningAlgValues,
        requiredClaims: ['sub', 'iat', 'exp', 'cnf'],
        typ: 'oauth-client-attestation+jwt',
        clockTolerance,
        subject: ctx.oidc.client.clientId,
      },
    );
    if (verifiedAttestation.key.type !== 'public') {
      throw new Error('the resolved key must be a public key');
    }
    if (
      typeof verifiedAttestation.payload.cnf?.jwk?.kty !== 'string'
      || verifiedAttestation.payload.cnf?.jwk?.d !== undefined
      || verifiedAttestation.payload.cnf?.jwk?.priv !== undefined
      || verifiedAttestation.payload.cnf?.jwk?.k !== undefined
    ) {
      throw new Error('invalid cnf.jwk');
    }
  } catch (cause) {
    throw invalid(ErrorClass, { cause });
  }

  const pop = ctx.get('oauth-client-attestation-pop');
  const combined = ctx.headers['oauth-client-attestation-pop'] === undefined
    && ctx.headers.dpop !== undefined;
  if (!pop && !combined) {
    throw invalid(ErrorClass, 'oauth-client-attestation-pop missing');
  }
  let verifiedPoP;
  let dPoP;
  if (combined) {
    if (!dPoPConfig.enabled) {
      throw invalid(ErrorClass, 'DPoP combined mode is not supported');
    }
    dPoP = await validateDpop(ctx.oidc.provider, ctx);
    if (!dPoP) {
      throw invalid(ErrorClass, 'DPoP proof missing');
    }
    verifiedPoP = getDpopJwt(ctx.oidc.provider, ctx);
    if (!verifiedPoP.payload.nonce) {
      ctx.set('dpop-nonce', DPoPNonces.nextChallenge());
      throw new UseDpopNonce('nonce is required in the DPoP proof');
    }
    let thumbprint;
    try {
      thumbprint = await jose.calculateJwkThumbprint(verifiedAttestation.payload.cnf.jwk);
    } catch (cause) {
      throw invalid(ErrorClass, { cause });
    }
    if (thumbprint !== dPoP.thumbprint) {
      throw invalid(ErrorClass, 'DPoP proof key does not match the Client Attestation key');
    }
  } else {
    try {
      verifiedPoP = await jose.jwtVerify(
        pop,
        async (header) => jose.importJWK(verifiedAttestation.payload.cnf.jwk, header.alg),
        {
          algorithms: attestSigningAlgValues,
          requiredClaims: ['aud', 'jti', 'iat'], // challenge is checked later
          typ: 'oauth-client-attestation-pop+jwt',
          clockTolerance,
          audience: ctx.oidc.issuer,
        },
      );
      if (typeof verifiedPoP.payload.aud !== 'string') {
        throw new Error('aud must be a string');
      }
      if (typeof verifiedPoP.payload.jti !== 'string' || !verifiedPoP.payload.jti) {
        throw new Error('jti must be a non-empty string');
      }
    } catch (cause) {
      throw invalid(ErrorClass, { cause });
    }
  }

  await attestClientAuth.assertAttestationJwtAndPop(
    ctx,
    verifiedAttestation,
    verifiedPoP,
    ctx.oidc.client,
  );

  if (combined) {
    ctx.oidc.clientAttestation = {
      method: 'dpop_combined',
      signal,
      attestation: verifiedAttestation,
      pop: verifiedPoP,
    };
    await checkDpopReplay(
      ctx.oidc.provider, ctx, dPoP, ctx.oidc.client.clientId, InvalidDpopProof,
    );
    return;
  }

  const unique = await ctx.oidc.provider.ReplayDetection.unique(
    ctx.oidc.client.clientId,
    verifiedPoP.payload.jti,
    epochTime() + CHALLENGE_OK_WINDOW,
  );

  if (!unique) {
    throw invalid(ErrorClass, 'oauth-client-attestation-pop tokens must only be used once');
  }

  const nextChallenge = AttestChallenges.nextChallenge();
  if (typeof verifiedPoP.payload.challenge !== 'string' || !AttestChallenges.checkChallenge(verifiedPoP.payload.challenge)) {
    ctx.set('oauth-client-attestation-challenge', nextChallenge);
    throw new UseAttestationChallenge();
  }

  if (verifiedPoP.payload.challenge !== nextChallenge) {
    ctx.set('oauth-client-attestation-challenge', nextChallenge);
  }

  ctx.oidc.clientAttestation = {
    method: 'attestation_pop_jwt',
    signal,
    attestation: verifiedAttestation,
    pop: verifiedPoP,
  };
}

export default function attestationClientAuth(ctx) {
  return validateClientAttestationJwtAndPop(ctx);
}
