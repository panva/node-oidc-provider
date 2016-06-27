'use strict';

module.exports = function getRefreshToken(provider) {
  const BaseOauthToken = provider.get('OAuthToken');
  return class RefreshToken extends BaseOauthToken {};
};
