import * as crypto from 'node:crypto';

import {
  calculateJwkThumbprint,
  EmbeddedJWK,
  jwtVerify,
} from 'jose';
import assertProviderContext from './assert_provider_context.js';
import { CHALLENGE_OK_WINDOW } from './challenge.js';
import { boolean } from './configuration_result.js';
import epochTime from './epoch_time.js';
import { InvalidDpopProof, InvalidGrant, UseDpopNonce } from './errors.js';
import instance from './weak_cache.js';

const weakMap = new WeakMap();

export async function checkDpopReplay(provider, ctx, dPoP, clientId, ErrorClass = InvalidGrant) {
  assertProviderContext(provider, ctx);

  if (!dPoP || instance(provider).features.dPoP.allowReplay) {
    return;
  }

  const unique = await provider.ReplayDetection.unique(
    clientId,
    dPoP.jti,
    epochTime() + CHALLENGE_OK_WINDOW,
  );

  ctx.assert(unique, new ErrorClass('DPoP proof JWT Replay detected'));
}

export default async function validateDpop(provider, ctx, accessToken) {
  assertProviderContext(provider, ctx);

  if (weakMap.has(ctx)) {
    return weakMap.get(ctx);
  }

  const {
    features: { dPoP: dPoPConfig },
    dPoPSigningAlgValues,
  } = instance(provider).configuration;

  if (!dPoPConfig.enabled) {
    return undefined;
  }

  const proof = ctx.get('DPoP');

  if (!proof) {
    return undefined;
  }

  const { DPoPNonces } = instance(provider);

  const requireNonce = boolean(dPoPConfig.requireNonce(ctx), 'features.dPoP.requireNonce');
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
      if (typeof payload.htu !== 'string') {
        throw new InvalidDpopProof('DPoP proof htu mismatch');
      }
      const actual = URL.parse(payload.htu);
      if (!actual) {
        throw new InvalidDpopProof('DPoP proof htu mismatch');
      }
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
  } catch (cause) {
    if (cause instanceof InvalidDpopProof || cause instanceof UseDpopNonce) {
      throw cause;
    }
    throw new InvalidDpopProof('invalid DPoP key binding', { cause });
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
}
