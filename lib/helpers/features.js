export const STABLE = new Set([
  'backchannelLogout',
  'ciba',
  'claimsParameter',
  'clientCredentials',
  'deviceFlow',
  'devInteractions',
  'dPoP',
  'encryption',
  'fapi',
  'introspection',
  'jwtResponseModes',
  'jwtIntrospection',
  'jwtUserinfo',
  'mTLS',
  'pushedAuthorizationRequests',
  'registration',
  'registrationManagement',
  'requestObjects',
  'resourceIndicators',
  'richAuthorizationRequests',
  'revocation',
  'rpInitiatedLogout',
  'rpMetadataChoices',
  'userinfo',
]);

export const EXPERIMENTS = new Map(Object.entries({
  openid4vci: {
    name: 'OpenID for Verifiable Credential Issuance 1.0',
    version: ['experimental-01'],
  },
  webMessageResponseMode: {
    name: 'OAuth 2.0 Web Message Response Mode - draft 01',
    version: ['individual-draft-01'],
  },
  externalSigningSupport: {
    name: 'External Signing Key Support',
    version: ['experimental-01'],
  },
  attestClientAuth: {
    name: 'OAuth 2.0 Attestation-Based Client Authentication',
    version: 'draft-10',
  },
  clientIdMetadataDocument: {
    name: 'OAuth Client ID Metadata Document',
    version: 'draft-02',
  },
}));
