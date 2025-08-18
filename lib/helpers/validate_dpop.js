import * as crypto from 'node:crypto';

import {
  jwtVerify,
  EmbeddedJWK,
  calculateJwkThumbprint,
} from 'jose';

import { InvalidDpopProof, UseDpopNonce } from './errors.js';
import instance from './weak_cache.js';
import epochTime from './epoch_time.js';
import { CHALLENGE_OK_WINDOW } from './challenge.js';

export { CHALLENGE_OK_WINDOW };

const weakMap = new WeakMap();

export default async (ctx, accessToken) => {
  if (weakMap.has(ctx)) {
    return weakMap.get(ctx);
  }

  const {
    features: { dPoP: dPoPConfig },
    dPoPSigningAlgValues,
  } = instance(ctx.oidc.provider).configuration;

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
  if (requireNonce && !DPoPNonces) {
    throw new Error('features.dPoP.nonceSecret configuration is missing');
  }

  const nextNonce = DPoPNonces?.nextChallenge();
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
      if (diff > CHALLENGE_OK_WINDOW) {
        if (nextNonce) {
          ctx.set('dpop-nonce', nextNonce);
          throw new UseDpopNonce('DPoP proof iat is not recent enough, use a DPoP nonce instead');
        }
        throw new InvalidDpopProof('DPoP proof iat is not recent enough');
      }
    } else if (!DPoPNonces) {
      throw new InvalidDpopProof('DPoP nonces are not supported');
    }

    if (payload.htm !== ctx.method) {
      throw new InvalidDpopProof('DPoP proof htm mismatch');
    }

    {
      const expected = new URL(ctx.oidc.urlFor(ctx.oidc.route)).href;
      const actual = URL.parse(payload.htu);
      if (!actual) return false;
      actual.hash = '';
      actual.search = '';

      if (actual?.href !== expected) {
        throw new InvalidDpopProof('DPoP proof htu mismatch');
      }
    }

    if (accessToken) {
      const ath = crypto.hash('sha256', accessToken, 'base64url');
      if (payload.ath !== ath) {
        throw new InvalidDpopProof('DPoP proof ath mismatch');
      }
    }
  } catch (err) {
    if (err instanceof InvalidDpopProof || err instanceof UseDpopNonce) {
      throw err;
    }
    throw new InvalidDpopProof('invalid DPoP key binding', err.message);
  }

  if (!payload.nonce && requireNonce) {
    ctx.set('dpop-nonce', nextNonce);
    throw new UseDpopNonce('nonce is required in the DPoP proof');
  }

  if (payload.nonce && !DPoPNonces.checkChallenge(payload.nonce)) {
    ctx.set('dpop-nonce', nextNonce);
    throw new UseDpopNonce('invalid nonce in DPoP proof');
  }

  if (payload.nonce !== nextNonce) {
    ctx.set('dpop-nonce', nextNonce);
  }

  const thumbprint = await calculateJwkThumbprint(protectedHeader.jwk);

  const result = { thumbprint, jti: payload.jti, iat: payload.iat };
  weakMap.set(ctx, result);

  return result;
};
