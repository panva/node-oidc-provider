'use strict';

module.exports = function getRefreshToken(provider) {
  const BaseOauthToken = provider.OAuthToken;
  return class RefreshToken extends BaseOauthToken {};
};
