'use strict';

module.exports = function getAccessToken(provider) {
  const BaseOauthToken = provider.get('OAuthToken');
  return class AccessToken extends BaseOauthToken {};
};
