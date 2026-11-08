import defaults from '../helpers/_/defaults.js';
import { getCredentialRequestEncryptionKeys } from '../helpers/credential_encryption.js';
import instance from '../helpers/weak_cache.js';

export default function openidCredentialIssuer(ctx) {
  const { features: { openid4vci }, enabledJWA } = instance(ctx.oidc.provider).configuration;

  const {
    credentialConfigurationsSupported,
    credentialRequestEncryption: request,
    credentialResponseEncryption: response,
  } = openid4vci;

  ctx.body = {
    credential_issuer: ctx.oidc.issuer,
    credential_endpoint: ctx.oidc.urlFor('credential'),
    nonce_endpoint: ctx.oidc.urlFor('challenge'),
    credential_configurations_supported: credentialConfigurationsSupported,
  };

  if (request) {
    ctx.body.credential_request_encryption = {
      jwks: getCredentialRequestEncryptionKeys(ctx.oidc.provider),
      enc_values_supported: enabledJWA.credentialEncryptionEncValues,
      encryption_required: request.required,
    };
  }
  if (response) {
    ctx.body.credential_response_encryption = {
      alg_values_supported: enabledJWA.credentialEncryptionAlgValues,
      enc_values_supported: enabledJWA.credentialEncryptionEncValues,
      encryption_required: response.required,
    };
  }

  defaults(ctx.body, openid4vci.metadata);
}
