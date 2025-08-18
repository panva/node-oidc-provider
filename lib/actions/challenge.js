import instance from '../helpers/weak_cache.js';
import noCache from '../shared/no_cache.js';

export default [
  noCache,
  function challenge(ctx) {
    const { DPoPNonces, AttestChallenges } = instance(ctx.oidc.provider);

    ctx.body = {};

    const nextNonce = DPoPNonces?.nextChallenge();
    if (nextNonce) {
      ctx.set('dpop-nonce', nextNonce);
    }

    const nextChallenge = AttestChallenges?.nextChallenge();
    if (nextChallenge) {
      ctx.set('oauth-client-attestation-challenge', nextChallenge);
      ctx.body.attestation_challenge = nextChallenge;
    }
  },
];
