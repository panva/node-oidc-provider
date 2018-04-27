const { struct, notEmpty } = require('../../struct');
const feature = require('./feature');
const uuid = require('uuid/v4');
const crypto = require('crypto');
const { features: defaults } = require('../../../lib/helpers/defaults');

function dependant(dependency) {
  return ({ enabled }, features) => {
    if (enabled && !features[dependency].enabled) return `is only available in conjuction with ${dependency}`;
    return true;
  };
}

module.exports = struct.intersection([
  struct({
    devInteractions: feature(defaults.devInteractions),
    discovery: feature(defaults.discovery),
    requestUri: feature(defaults.requestUri, {
      requireRequestUriRegistration: 'boolean',
    }, {
      requireRequestUriRegistration: false,
    }),
    oauthNativeApps: feature(defaults.oauthNativeApps),
    pkce: feature(defaults.pkce, {
      forcedForNative: 'boolean',
      supportedMethods: notEmpty([struct.enum(['plain', 'S256'])]),
    }, {
      forcedForNative: true,
      supportedMethods: ['S256'],
    }),
    backchannelLogout: feature(defaults.backchannelLogout),
    frontchannelLogout: feature(defaults.frontchannelLogout),
    claimsParameter: feature(defaults.claimsParameter),
    clientCredentials: feature(defaults.clientCredentials),
    encryption: feature(defaults.encryption),
    introspection: feature(defaults.introspection),
    alwaysIssueRefresh: feature(defaults.alwaysIssueRefresh),
    registration: feature(defaults.registration, {
      initialAccessToken: 'string | boolean',
      idFactory: 'function',
      secretFactory: 'function',
    }, {
      initialAccessToken: false,
      idFactory: () => uuid,
      secretFactory: () => () => crypto.randomBytes(48).toString('base64'),
    }),
    registrationManagement: feature(defaults.registrationManagement, {
      rotateRegistrationAccessToken: 'boolean',
    }, {
      rotateRegistrationAccessToken: false,
    }),
    request: feature(defaults.request),
    revocation: feature(defaults.revocation),
    sessionManagement: feature(defaults.sessionManagement, {
      keepHeaders: 'boolean',
    }, {
      keepHeaders: false,
    }),
  }, {}),
  struct.interface({
    registrationManagement: dependant('registration'),
    backchannelLogout: dependant('sessionManagement'),
    frontchannelLogout: dependant('sessionManagement'),
  }),
]);
