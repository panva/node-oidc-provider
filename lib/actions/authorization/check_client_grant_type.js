const { UnauthorizedClient } = require('../../helpers/errors');

module.exports = function checkClientGrantType({ oidc: { client: { grantTypes } } }, next) {
  if (!grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')) {
    throw new UnauthorizedClient('device flow not allowed for this client');
  }
  return next();
};
