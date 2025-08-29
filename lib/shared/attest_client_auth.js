import * as jose from 'jose';

import { InvalidClientAuth, UseAttestationChallenge } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import { CHALLENGE_OK_WINDOW } from '../helpers/challenge.js';
import epochTime from '../helpers/epoch_time.js';

export default async function attestationClientAuth(ctx) {
  const {
    configuration: {
      clockTolerance,
      features: { attestClientAuth },
      attestSigningAlgValues,
    },
    AttestChallenges,
  } = instance(ctx.oidc.provider);

  const nextChallenge = AttestChallenges.nextChallenge();

  const attestation = ctx.get('oauth-client-attestation');
  let verifiedAttestation;
  try {
    verifiedAttestation = await jose.jwtVerify(
      attestation,
      async (header) => {
        const payload = jose.decodeJwt(attestation);
        if (typeof payload.iss !== 'string') {
          throw new Error('iss must be a string');
        }
        const key = await attestClientAuth.getAttestationSignaturePublicKey(
          ctx,
          payload.iss,
          header,
          ctx.oidc.client,
        );
        return key;
      },
      {
        algorithms: attestSigningAlgValues,
        requiredClaims: ['iss', 'sub', 'exp', 'cnf'],
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
  } catch (err) {
    throw new InvalidClientAuth(`failed to validate oauth-client-attestation: ${err.message}`);
  }

  const pop = ctx.get('oauth-client-attestation-pop');
  if (!pop) {
    throw new InvalidClientAuth('oauth-client-attestation-pop missing');
  }
  let verifiedPoP;
  try {
    verifiedPoP = await jose.jwtVerify(
      pop,
      async (header) => jose.importJWK(verifiedAttestation.payload.cnf.jwk, header.alg),
      {
        algorithms: attestSigningAlgValues,
        requiredClaims: ['iss', 'aud', 'jti'], // challenge is checked later
        typ: 'oauth-client-attestation-pop+jwt',
        clockTolerance,
        issuer: ctx.oidc.client.clientId,
        audience: ctx.oidc.issuer,
      },
    );
    if (typeof verifiedPoP.payload.aud !== 'string') {
      throw new Error('aud must be a string');
    }
  } catch (err) {
    throw new InvalidClientAuth(`failed to validate oauth-client-attestation-pop: ${err.message}`);
  }

  await attestClientAuth.assertAttestationJwtAndPop(
    ctx,
    verifiedAttestation,
    verifiedPoP,
    ctx.oidc.client,
  );

  const unique = await ctx.oidc.provider.ReplayDetection.unique(
    verifiedPoP.payload.iss,
    verifiedPoP.payload.jti,
    epochTime() + CHALLENGE_OK_WINDOW,
  );

  if (!unique) {
    throw new InvalidClientAuth('oauth-client-attestation-pop tokens must only be used once');
  }

  if (typeof verifiedPoP.payload.challenge !== 'string' || !AttestChallenges.checkChallenge(verifiedPoP.payload.challenge)) {
    ctx.set('oauth-client-attestation-challenge', nextChallenge);
    throw new UseAttestationChallenge();
  }

  if (verifiedPoP.payload.challenge !== nextChallenge) {
    ctx.set('oauth-client-attestation-challenge', nextChallenge);
  }
}
