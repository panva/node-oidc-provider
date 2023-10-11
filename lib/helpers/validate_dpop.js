import { createHash } from 'node:crypto';

import {
  jwtVerify,
  EmbeddedJWK,
  calculateJwkThumbprint,
} from 'jose';

import { InvalidDpopProof, UseDpopNonce } from './errors.js';
import instance from './weak_cache.js';
import * as base64url from './base64url.js';
import epochTime from './epoch_time.js';

export default async (ctx, accessToken) => {
  const {
    features: { dPoP: dPoPConfig },
    dPoPSigningAlgValues,
  } = instance(ctx.oidc.provider).configuration();

  if (!dPoPConfig.enabled) {
    return undefined;
  }

  const proof = ctx.get('DPoP');

  if (!proof) {
    return undefined;
  }

  const { DPoPNonces } = instance(ctx.oidc.provider);

  const requireNonce = dPoPConfig.requireNonce(ctx);
  if (typeof requireNonce !== 'boolean') {
    throw new Error('features.dPoP.requireNonce must return a boolean');
  }

  if (DPoPNonces) {
    ctx.set('DPoP-Nonce', DPoPNonces.nextNonce());
  } else if (requireNonce) {
    throw new Error('features.dPoP.nonceSecret configuration is missing');
  }

  let payload;
  let protectedHeader;
  try {
    ({ protectedHeader, payload } = await jwtVerify(proof, EmbeddedJWK, { algorithms: dPoPSigningAlgValues, typ: 'dpop+jwt' }));

    if (typeof payload.iat !== 'number' || !payload.iat) {
      throw new InvalidDpopProof('DPoP proof must have a iat number property');
    }

    if (typeof payload.jti !== 'string' || !payload.jti) {
      throw new InvalidDpopProof('DPoP proof must have a jti string property');
    }

    if (payload.nonce !== undefined && typeof payload.nonce !== 'string') {
      throw new InvalidDpopProof('DPoP proof nonce must be a string');
    }

    if (!payload.nonce) {
      const now = epochTime();
      const diff = Math.abs(now - payload.iat);
      if (diff > 300) {
        throw new InvalidDpopProof('DPoP proof iat is not recent enough');
      }
    }

    if (payload.htm !== ctx.method) {
      throw new InvalidDpopProof('DPoP proof htm mismatch');
    }

    {
      const expected = new URL(ctx.oidc.urlFor(ctx.oidc.route)).href;
      let actual;
      try {
        actual = new URL(payload.htu);
        actual.hash = '';
        actual.search = '';
      } catch {}

      if (actual?.href !== expected) {
        throw new InvalidDpopProof('DPoP proof htu mismatch');
      }
    }

    if (accessToken) {
      const ath = base64url.encode(createHash('sha256').update(accessToken).digest());
      if (payload.ath !== ath) {
        throw new InvalidDpopProof('DPoP proof ath mismatch');
      }
    }
  } catch (err) {
    if (err instanceof InvalidDpopProof) {
      throw err;
    }
    throw new InvalidDpopProof('invalid DPoP key binding', err.message);
  }

  if (!payload.nonce && requireNonce) {
    throw new UseDpopNonce('nonce is required in the DPoP proof');
  }

  if (payload.nonce && (!DPoPNonces || !DPoPNonces.checkNonce(payload.nonce))) {
    throw new UseDpopNonce('invalid nonce in DPoP proof');
  }

  const thumbprint = await calculateJwkThumbprint(protectedHeader.jwk);

  return { thumbprint, jti: payload.jti, iat: payload.iat };
};
