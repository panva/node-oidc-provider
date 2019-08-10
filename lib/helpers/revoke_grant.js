const instance = require('./weak_cache');

const DC = 'urn:ietf:params:oauth:grant-type:device_code';

module.exports = async function revokeGrant(provider, client, grantId) {
  const { grantTypes } = instance(provider).configuration();
  const refreshToken = client ? client.grantTypes.includes('refresh_token') : grantTypes.has('refresh_token');
  const authorizationCode = client ? client.grantTypes.includes('authorization_code') : grantTypes.has('authorization_code');
  const deviceCode = client ? client.grantTypes.includes(DC) : grantTypes.has(DC);

  await Promise.all([
    provider.AccessToken,
    refreshToken ? provider.RefreshToken : undefined,
    authorizationCode ? provider.AuthorizationCode : undefined,
    deviceCode ? provider.DeviceCode : undefined,
  ].filter(Boolean).map((model) => model.revokeByGrantId(grantId)));
};
