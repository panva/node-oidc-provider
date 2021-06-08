const STABLE = new Set([
  'claimsParameter',
  'clientCredentials',
  'deviceFlow',
  'devInteractions',
  'encryption',
  'introspection',
  'jwtUserinfo',
  'mTLS',
  'fapi',
  'registration',
  'registrationManagement',
  'requestObjects',
  'resourceIndicators',
  'revocation',
  'rpInitiatedLogout',
  'userinfo',
]);

const DRAFTS = new Map(Object.entries({
  backchannelLogout: {
    name: 'OpenID Connect Back-Channel Logout 1.0 - draft 06',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-backchannel-1_0-06.html',
    version: [4, 'draft-04', 'draft-05', 'draft-06'],
  },
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
  jwtResponseModes: {
    name: 'JWT Secured Authorization Response Mode for OAuth 2.0 - Implementer\'s Draft 01',
    type: 'OIDF FAPI WG Implementer\'s Draft',
    url: 'https://openid.net/specs/openid-financial-api-jarm-ID1.html',
    version: [1, 2, 'draft-02', 'implementers-draft-01'],
  },
  pushedAuthorizationRequests: {
    name: 'OAuth 2.0 Pushed Authorization Requests - draft 08',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-par-08',
    version: [0, 'individual-draft-01', 'draft-00', 'draft-01', 'draft-02', 'draft-03', 'draft-04', 'draft-05', 'draft-06', 'draft-07', 'draft-08'],
  },
  webMessageResponseMode: {
    name: 'OAuth 2.0 Web Message Response Mode - draft 00',
    type: 'Individual draft',
    url: 'https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00',
    version: [0, 'id-00', 'individual-draft-00'],
  },
  issAuthResp: {
    name: 'OAuth 2.0 Authorization Server Issuer Identifier in Authorization Response - draft 01',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp-01',
    version: ['draft-00', 'draft-01'],
  },
  ciba: {
    name: 'OpenID Connect Client Initiated Backchannel Authentication Flow - Core 1.0 - draft 03',
    type: 'OIDF MODRNA Working Group draft',
    url: 'https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-03.html',
    version: ['draft-03'],
  },
}));

module.exports = {
  DRAFTS,
  STABLE,
};
