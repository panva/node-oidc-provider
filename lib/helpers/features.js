const STABLE = new Set([
  'claimsParameter',
  'clientCredentials',
  'deviceFlow',
  'devInteractions',
  'encryption',
  'introspection',
  'jwtUserinfo',
  'mTLS',
  'registration',
  'registrationManagement',
  'requestObjects',
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
  ietfJWTAccessTokenProfile: {
    name: 'JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens - draft 05',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-05',
    version: [2, 'draft-02', 'draft-03', 'draft-04', 'draft-05'],
  },
  fapiRW: {
    name: 'Financial-grade API - Part 2: Read and Write API Security Profile',
    type: 'OIDF FAPI Working Group draft',
    url: 'https://openid.net/specs/openid-financial-api-part-2-ID2.html',
    version: ['id02-rev.3', 'implementers-draft-02'],
  },
  dPoP: {
    name: 'OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-dpop-01',
    version: ['draft-01'],
  },
  frontchannelLogout: {
    name: 'OpenID Connect Front-Channel Logout 1.0 - draft 04',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-frontchannel-1_0-04.html',
    version: [2, 'draft-02', 'draft-03', 'draft-04'],
  },
  jwtIntrospection: {
    name: 'JWT Response for OAuth Token Introspection - draft 09',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-09',
    version: ['draft-09'],
  },
  jwtResponseModes: {
    name: 'JWT Secured Authorization Response Mode for OAuth 2.0 - draft 02',
    type: 'OIDF FAPI WG draft',
    url: 'https://openid.net/specs/openid-financial-api-jarm-wd-02.html',
    version: [1, 2, 'draft-02'],
  },
  pushedAuthorizationRequests: {
    name: 'OAuth 2.0 Pushed Authorization Requests - draft 03',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-par-03',
    version: [0, 'individual-draft-01', 'draft-00', 'draft-01', 'draft-02', 'draft-03'],
  },
  resourceIndicators: {
    name: 'Resource Indicators for OAuth 2.0 - draft 08',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-08',
    version: [2, 3, 4, 5, 6, 7, 'draft-07', 'draft-08'],
  },
  sessionManagement: {
    name: 'OpenID Connect Session Management 1.0 - draft 30',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-session-1_0-30.html',
    version: [28, 'draft-28', 'draft-29', 'draft-30'],
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
