const STABLE = new Set([
  'claimsParameter',
  'clientCredentials',
  'deviceFlow',
  'devInteractions',
  'encryption',
  'introspection',
  'jwtUserinfo',
  'registration',
  'registrationManagement',
  'requestObjects',
  'revocation',
  'userinfo',
]);

const DRAFTS = new Map(Object.entries({
  backchannelLogout: {
    name: 'OpenID Connect Back-Channel Logout 1.0 - draft 04',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-backchannel-1_0-04.html',
    version: 4,
  },
  ietfJWTAccessTokenProfile: {
    name: 'JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens - draft 02',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-02',
    version: 2,
  },
  fapiRW: {
    name: 'Financial-grade API - Part 2: Read and Write API Security Profile',
    type: 'OIDF FAPI Working Group draft',
    url: 'https://openid.net/specs/openid-financial-api-part-2-ID2.html',
    version: 'id02-rev.2',
  },
  mTLS: {
    name: 'OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens - draft 17',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-mtls-17',
    version: ['15-rc.1', 16, 17],
  },
  dPoP: {
    name: 'OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer',
    type: 'Individual draft',
    url: 'https://tools.ietf.org/html/draft-fett-oauth-dpop-02',
    version: 'id-02',
  },
  frontchannelLogout: {
    name: 'OpenID Connect Front-Channel Logout 1.0 - draft 02',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-frontchannel-1_0-02.html',
    version: 2,
  },
  jwtIntrospection: {
    name: 'JWT Response for OAuth Token Introspection - draft 07',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-07',
    version: [2, 3, 4, 5, 6, 7],
  },
  jwtResponseModes: {
    name: 'JWT Secured Authorization Response Mode for OAuth 2.0 - draft 02',
    type: 'OIDF FAPI WG draft',
    url: 'https://openid.net/specs/openid-financial-api-jarm-wd-02.html',
    version: [1, 2],
  },
  // TODO: push this to README.md once published by IETF and/or OIDC
  pushedRequestObjects: {
    name: 'Pushed Request Object',
    type: 'OIDF FAPI WG draft',
    url: 'https://bitbucket.org/openid/fapi/src/b6cd952/Financial_API_Pushed_Request_Object.md',
    version: 'b6cd952',
  },
  resourceIndicators: {
    name: 'Resource Indicators for OAuth 2.0 - draft 07',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-07',
    version: [2, 3, 4, 5, 6, 7],
  },
  sessionManagement: {
    name: 'OpenID Connect Session Management 1.0 - draft 28',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-session-1_0-28.html',
    version: 28,
  },
  webMessageResponseMode: {
    name: 'OAuth 2.0 Web Message Response Mode - draft 00',
    type: 'Individual draft',
    url: 'https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00',
    version: [0, 'id-00'],
  },
}));

module.exports = {
  DRAFTS,
  STABLE,
};
