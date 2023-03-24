/* eslint-disable max-len */
import instance from '../helpers/weak_cache.js';

export default function discovery(ctx, next) {
  const config = instance(ctx.oidc.provider).configuration();
  const { routes, features: { credential } } = config;

  ctx.body = {
    credential_issuer: ctx.oidc.issuer,
    credential_endpoint: `${ctx.oidc.issuer}${routes.credential}`,
    credentials_supported: credential.credentialsSupported,
  }

  return next();
}
