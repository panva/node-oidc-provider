const STABLE = new Set([
  'claimsParameter',
  'clientCredentials',
  'devInteractions',
  'encryption',
  'introspection',
  'jwtUserinfo',
  'registration',
  'registrationManagement',
  'request',
  'requestUri',
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
  mTLS: {
    name: 'OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens - draft 15',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-mtls-15',
    version: '15-rc.1',
  },
  deviceFlow: {
    name: 'OAuth 2.0 Device Authorization Grant - draft 15',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15',
    version: 15,
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
    name: 'JWT Response for OAuth Token Introspection - draft 03',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-03',
    version: [2, 3],
  },
  jwtResponseModes: {
    name: 'JWT Secured Authorization Response Mode for OAuth 2.0 - draft 02',
    type: 'OIDF FAPI WG draft',
    url: 'https://openid.net/specs/openid-financial-api-jarm-wd-02.html',
    version: [1, 2],
  },
  resourceIndicators: {
    name: 'Resource Indicators for OAuth 2.0 - draft 03',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-03',
    version: [2, 3],
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
