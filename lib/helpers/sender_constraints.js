import { InvalidGrant } from './errors.js';
import instance from './weak_cache.js';
import validateDpop, { checkDpopReplay } from './validate_dpop.js';
import assertProviderContext from './assert_provider_context.js';

export async function validateSenderConstraints(provider, ctx, ErrorClass = InvalidGrant) {
  assertProviderContext(provider, ctx);

  const dPoP = await validateDpop(ctx);
  let certificate;

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    certificate = instance(provider).configuration.features.mTLS.getCertificate(ctx);
    if (!certificate) {
      throw new ErrorClass('mutual TLS client certificate not provided');
    }
  }

  if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
    throw new ErrorClass('DPoP proof JWT not provided');
  }

  if (certificate && dPoP) {
    throw new ErrorClass('multiple proof-of-possession mechanisms are not allowed');
  }

  return { certificate, dPoP };
}

export async function applySenderConstraints(
  provider,
  ctx,
  token,
  { certificate, dPoP },
  ErrorClass = InvalidGrant,
) {
  assertProviderContext(provider, ctx);

  if (
    (certificate && dPoP)
    || (certificate && token.jkt)
    || (dPoP && token['x5t#S256'])
  ) {
    throw new ErrorClass('multiple proof-of-possession mechanisms are not allowed');
  }

  if (certificate) {
    token.setThumbprint('x5t', certificate);
  }

  if (dPoP) {
    await checkDpopReplay(provider, ctx, dPoP, ctx.oidc.client.clientId, ErrorClass);
    token.setThumbprint('jkt', dPoP.thumbprint);
  }
}
