'use strict';

module.exports = function getAccessToken(provider) {
  const BaseOauthToken = provider.OAuthToken;
  return class AccessToken extends BaseOauthToken {};
};
