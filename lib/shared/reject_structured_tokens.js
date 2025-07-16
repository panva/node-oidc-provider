import { decodeProtectedHeader } from 'jose';

import { UnsupportedTokenType } from '../helpers/errors.js';

export default async function rejectStructuredTokens(ctx, next) {
  const { params } = ctx.oidc;

  let tokenIsJWT;
  try {
    tokenIsJWT = !!decodeProtectedHeader(params.token);
  } catch {}

  if (tokenIsJWT) {
    throw new UnsupportedTokenType(`Structured JWT Tokens cannot be ${ctx.oidc.route === 'revocation' ? 'revoked' : 'introspected'} via the ${ctx.oidc.route}_endpoint`);
  }

  return next();
}
