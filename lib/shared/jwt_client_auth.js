import { InvalidClientAuth } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import * as JWT from '../helpers/jwt.js';

export default async function jwtClientAuth(ctx, keystore, filter) {
  const {
    clockTolerance,
    assertJwtClientAuthClaimsAndHeader,
    clientAuthSigningAlgValues,
  } = instance(ctx.oidc.provider).configuration;

  const acceptedAud = ctx.oidc.clientJwtAuthExpectedAudience();
  const { header, payload } = JWT.decode(ctx.oidc.params.client_assertion);

  if (ctx.oidc.client.clientAuthSigningAlg) {
    if (header.alg !== ctx.oidc.client.clientAuthSigningAlg) {
      throw new InvalidClientAuth('alg mismatch');
    }
  } else {
    const algorithms = clientAuthSigningAlgValues.filter(filter);
    if (!algorithms.includes(header.alg)) {
      throw new InvalidClientAuth('alg mismatch');
    }
  }

  if (!payload.exp) {
    throw new InvalidClientAuth('expiration must be specified in the client_assertion JWT');
  }

  if (!payload.jti) {
    throw new InvalidClientAuth('unique jti (JWT ID) must be provided in the client_assertion JWT');
  }

  if (!payload.iss) {
    throw new InvalidClientAuth('iss (JWT issuer) must be provided in the client_assertion JWT');
  }

  if (payload.iss !== ctx.oidc.client.clientId) {
    throw new InvalidClientAuth('iss (JWT issuer) must be the client_id');
  }

  if (!payload.aud) {
    throw new InvalidClientAuth('aud (JWT audience) must be provided in the client_assertion JWT');
  }

  if (Array.isArray(payload.aud)) {
    if (!payload.aud.some((aud) => acceptedAud.has(aud))) {
      throw new InvalidClientAuth('list of audience (aud) must include the endpoint url, issuer identifier or token endpoint url');
    }
  } else if (!acceptedAud.has(payload.aud)) {
    throw new InvalidClientAuth('audience (aud) must equal the endpoint url, issuer identifier or token endpoint url');
  }

  try {
    await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
      clockTolerance,
      ignoreAzp: true,
    });
  } catch (err) {
    throw new InvalidClientAuth(err.message);
  }

  await assertJwtClientAuthClaimsAndHeader(
    ctx,
    structuredClone(payload),
    structuredClone(header),
    ctx.oidc.client,
  );

  const unique = await ctx.oidc.provider.ReplayDetection.unique(
    payload.iss,
    payload.jti,
    payload.exp + clockTolerance,
  );

  if (!unique) {
    throw new InvalidClientAuth('client assertion tokens must only be used once');
  }
}
