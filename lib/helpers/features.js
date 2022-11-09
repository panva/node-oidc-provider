const STABLE = new Set([
  'backchannelLogout',
  'ciba',
  'claimsParameter',
  'clientCredentials',
  'deviceFlow',
  'devInteractions',
  'encryption',
  'fapi',
  'introspection',
  'jwtResponseModes',
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

const DRAFTS = new Map(Object.entries({
  dPoP: {
    name: 'OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer - draft 03',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-dpop-03',
    version: ['draft-03'],
  },
  jwtIntrospection: {
    name: 'JWT Response for OAuth Token Introspection - draft 10',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-10',
    version: ['draft-09', 'draft-10'],
  },
  webMessageResponseMode: {
    name: 'OAuth 2.0 Web Message Response Mode - draft 00',
    type: 'Individual draft',
    url: 'https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00',
    version: [0, 'id-00', 'individual-draft-00'],
  },
}));

module.exports = {
  DRAFTS,
  STABLE,
};
