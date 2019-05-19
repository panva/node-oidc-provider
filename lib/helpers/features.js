const STABLE = new Set([
  'claimsParameter',
  'clientCredentials',
  'devInteractions',
  'encryption',
  'introspection',
  'registration',
  'registrationManagement',
  'request',
  'requestUri',
  'revocation',
]);

const MTLS = 'https://tools.ietf.org/html/draft-ietf-oauth-mtls-14';
const MTLS_VERSION = 14;

const DRAFTS = new Map(Object.entries({
  backchannelLogout: {
    name: 'OpenID Connect Back-Channel Logout 1.0 - draft 04',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-backchannel-1_0-04.html',
    version: 4,
  },
  certificateBoundAccessTokens: {
    name: `Mutual TLS Client Certificate Bound Access Tokens - draft ${MTLS_VERSION}`,
    type: 'IETF OAuth Working Group draft',
    url: `${MTLS}#section-3`,
    version: MTLS_VERSION,
  },
  deviceFlow: {
    name: 'OAuth 2.0 Device Authorization Grant - draft 15',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15',
    version: 15,
  },
  frontchannelLogout: {
    name: 'OpenID Connect Front-Channel Logout 1.0 - draft 02',
    type: 'OIDF AB/Connect Working Group draft',
    url: 'https://openid.net/specs/openid-connect-frontchannel-1_0-02.html',
    version: 2,
  },
  jwtIntrospection: {
    name: 'JWT Response for OAuth Token Introspection - draft 02',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-02',
    version: 2,
  },
  jwtResponseModes: {
    name: 'JWT Secured Authorization Response Mode for OAuth 2.0 - draft 02',
    type: 'OIDF FAPI WG draft',
    url: 'https://openid.net/specs/openid-financial-api-jarm-wd-02.html',
    version: 1,
  },
  resourceIndicators: {
    name: 'Resource Indicators for OAuth 2.0 - draft 02',
    type: 'IETF OAuth Working Group draft',
    url: 'https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-02',
    version: 2,
  },
  selfSignedTlsClientAuth: {
    name: `Self-Signed Certificate Mutual TLS OAuth Client Authentication Method - draft ${MTLS_VERSION}`,
    type: 'IETF OAuth Working Group draft',
    url: `${MTLS}#section-2.2`,
    version: MTLS_VERSION,
  },
  tlsClientAuth: {
    name: `PKI Mutual TLS OAuth Client Authentication Method - draft ${MTLS_VERSION}`,
    type: 'IETF OAuth Working Group draft',
    url: `${MTLS}#section-2.1`,
    version: MTLS_VERSION,
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
    version: 0,
  },
}));

module.exports = {
  DRAFTS,
  STABLE,
};
