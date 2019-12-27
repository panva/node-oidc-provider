const { UnauthorizedClient } = require('../../helpers/errors');

module.exports = function checkClientGrantType({ oidc: { route, client } }, next) {
  let grantType;
  switch (route) {
    case 'device_authorization':
      grantType = 'urn:ietf:params:oauth:grant-type:device_code';
      break;
    /* istanbul ignore next */
    default:
      throw new Error('not implemented');
  }

  if (!client.grantTypeAllowed(grantType)) {
    throw new UnauthorizedClient(`${grantType} is not allowed for this client`);
  }

  return next();
};
