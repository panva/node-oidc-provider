const instance = require('./weak_cache');

module.exports = async function revokeGrant(provider, client, grantId) {
  const { grantTypes } = instance(provider).configuration();
  const refreshToken = client ? client.grantTypeAllowed('refresh_token') : grantTypes.has('refresh_token');
  const authorizationCode = client ? client.grantTypeAllowed('authorization_code') : grantTypes.has('authorization_code');
  const deviceCode = client ? client.grantTypeAllowed('urn:ietf:params:oauth:grant-type:device_code') : grantTypes.has('urn:ietf:params:oauth:grant-type:device_code');

  await Promise.all([
    provider.AccessToken,
    refreshToken ? provider.RefreshToken : undefined,
    authorizationCode ? provider.AuthorizationCode : undefined,
    deviceCode ? provider.DeviceCode : undefined,
  ].filter(Boolean).map((model) => model.revokeByGrantId(grantId)));
};
