import { EventEmitter } from 'node:events';

import { generateKeyPair } from 'jose';

import getConfig from '../default.config.js';
import {
  InvalidAuthorizationDetails,
  InvalidTarget,
} from '../../lib/helpers/errors.js';

export const attesterKeypair = await generateKeyPair('ES256', { extractable: true });
export const rarEvents = new EventEmitter();

const config = getConfig();

config.scopes = ['openid', 'offline_access', 'mdl_scope'];
config.enabledJWA.dPoPSigningAlgValues = ['ES256'];
config.features.dPoP = {
  enabled: true,
};
config.features.richAuthorizationRequests = {
  enabled: true,
  authorizationDetailsForGrantSource(ctx) {
    return ctx.oidc.grant.rar;
  },
  authorizationDetailsForAccessToken(ctx, token, source, grantType) {
    rarEvents.emit('authorizationDetailsForAccessToken', ctx, token, source, grantType);

    const requested = ctx.oidc.params.authorization_details
      ? JSON.parse(ctx.oidc.params.authorization_details)
      : source?.rar;

    if (!requested) return undefined;

    const granted = new Set(source?.rar?.map((detail) => detail.credential_configuration_id));
    if (requested.some((detail) => !granted.has(detail.credential_configuration_id))) {
      throw new InvalidAuthorizationDetails('requested authorization details were not granted');
    }

    return requested.map((detail) => ({
      ...detail,
      credential_identifiers: [`${detail.credential_configuration_id}-id-1`],
    }));
  },
  authorizationDetailsForIntrospection(_ctx, token) {
    return token.rar;
  },
};
config.features.resourceIndicators = {
  enabled: true,
  defaultResource(ctx) {
    return ctx.oidc.urlFor('credential');
  },
  useGrantedResource() {
    return true;
  },
  getResourceServerInfo(ctx, resource) {
    if (resource === ctx.oidc.urlFor('credential')) {
      return {
        audience: resource,
        scope: 'mdl_scope',
      };
    }

    throw new InvalidTarget();
  },
};
config.features.openid4vci = {
  enabled: true,
  ack: 'experimental-01',
  preAuthorizedCodeGrant: true,
  nonceSecret: Buffer.alloc(32, 0),
  async getKeyAttestationSignaturePublicKey(_ctx, iss) {
    if (iss !== 'https://wallet-provider.example.com') {
      throw new Error('unknown attestation issuer');
    }
    return attesterKeypair.publicKey;
  },
  metadata: {
    test_metadata_member: 'test-value',
    batch_credential_issuance: {
      batch_size: 2,
    },
  },
  credentialConfigurationsSupported: {
    'org.iso.18013.5.1.mDL': {
      format: 'mso_mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
      scope: 'mdl_scope',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
        },
      },
    },
    'org.iso.18013.5.1.mDL.jwt.attestation_required': {
      format: 'mso_mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
      scope: 'mdl_scope',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            key_storage: ['iso_18045_high', 'iso_18045_moderate'],
            user_authentication: ['iso_18045_moderate'],
          },
        },
      },
    },
    SD_JWT_VC_example_in_OpenID4VCI: {
      format: 'dc+sd-jwt',
      vct: 'SD_JWT_VC_example_in_OpenID4VCI',
      scope: 'mdl_scope',
    },
    'org.iso.18013.5.1.mDL.no_scope': {
      format: 'mso_mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
    },
    'org.iso.18013.5.1.mDL.attestation': {
      format: 'mso_mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
      scope: 'mdl_scope',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
        },
      },
    },
    'org.iso.18013.5.1.mDL.attestation.required': {
      format: 'mso_mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
      scope: 'mdl_scope',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            key_storage: ['iso_18045_high', 'iso_18045_moderate'],
            user_authentication: ['iso_18045_moderate'],
          },
        },
      },
    },
  },
  async credentialConfigurationPolicy() {
    return true;
  },
  async issueCredential(_ctx, {
    credentialConfigurationId,
    credentialIdentifier,
    proofs,
  }) {
    let proofType = 'none';
    if (proofs) {
      [proofType] = Object.keys(proofs);
    }

    return {
      credentials: [{
        credential: JSON.stringify({
          format: credentialConfigurationId,
          credential_identifier: credentialIdentifier,
          proof_type: proofType,
          ...(proofType === 'attestation' && proofs.attestation?.attestedKeys
            ? { attested_keys_count: proofs.attestation.attestedKeys.length }
            : {}),
          ...(proofType === 'jwt' && proofs.key_attestation?.attestedKeys
            ? { attested_keys_count: proofs.key_attestation.attestedKeys.length }
            : {}),
        }),
      }],
    };
  },
};

export default {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      authorization_details_types: ['openid_credential'],
    },
    {
      client_id: 'wallet',
      grant_types: ['urn:ietf:params:oauth:grant-type:pre-authorized_code', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      authorization_details_types: ['openid_credential'],
    },
    {
      client_id: 'wallet-other',
      grant_types: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      authorization_details_types: ['openid_credential'],
    },
  ],
};
