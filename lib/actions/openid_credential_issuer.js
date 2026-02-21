import defaults from '../helpers/_/defaults.js';
import instance from '../helpers/weak_cache.js';

export default function openidCredentialIssuer(ctx) {
  const { openid4vci } = instance(ctx.oidc.provider).configuration.features;

  const { credentialConfigurationsSupported } = openid4vci;

  ctx.body = {
    credential_issuer: ctx.oidc.issuer,
    credential_endpoint: ctx.oidc.urlFor('credential'),
    nonce_endpoint: ctx.oidc.urlFor('challenge'),
    credential_configurations_supported: credentialConfigurationsSupported,
  };

  defaults(ctx.body, openid4vci.metadata);
}
