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
  'revocation',
  'rpInitiatedLogout',
  'userinfo',
]);

export const EXPERIMENTS = new Map(Object.entries({
  richAuthorizationRequests: {
    name: 'OAuth 2.0 Rich Authorization Requests',
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
  rpMetadataChoices: {
    name: 'OpenID Connect Relying Party Metadata Choices',
    version: ['draft-02'],
  },
  attestClientAuth: {
    name: 'OAuth 2.0 Attestation-Based Client Authentication',
    version: 'draft-06',
  },
}));
