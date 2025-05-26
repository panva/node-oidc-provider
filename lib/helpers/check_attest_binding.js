import * as jose from 'jose';

import { InvalidGrant } from './errors.js';

export async function checkAttestBinding(ctx, model) {
  const { cnf: { jwk } } = jose.decodeJwt(ctx.get('oauth-client-attestation'));
  if (model.attestationJkt !== await jose.calculateJwkThumbprint(jwk)) {
    throw new InvalidGrant('oauth-client-attestation instance public key mismatch');
  }
}
