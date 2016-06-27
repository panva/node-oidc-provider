'use strict';

module.exports = function getAuthorizationCode(provider) {
  const BaseOauthToken = provider.get('OAuthToken');
  return class AuthorizationCode extends BaseOauthToken {};
};
