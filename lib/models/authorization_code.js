'use strict';

module.exports = function getAuthorizationCode(provider) {
  const BaseOauthToken = provider.OAuthToken;
  return class AuthorizationCode extends BaseOauthToken {};
};
