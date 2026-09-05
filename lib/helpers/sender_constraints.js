import { InvalidGrant } from './errors.js';
import instance from './weak_cache.js';
import assertProviderContext from './assert_provider_context.js';

export function checkMtlsCert(provider, ctx, ErrorClass = InvalidGrant) {
  assertProviderContext(provider, ctx);

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    const certificate = instance(provider).configuration.features.mTLS.getCertificate(ctx);
    if (!certificate) {
      throw new ErrorClass('mutual TLS client certificate not provided');
    }
    return certificate;
  }
  return undefined;
}

export function checkDpopRequired(provider, ctx, dPoP, ErrorClass = InvalidGrant) {
  assertProviderContext(provider, ctx);

  if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
    throw new ErrorClass('DPoP proof JWT not provided');
  }
}
