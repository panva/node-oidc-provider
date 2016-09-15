'use strict';

module.exports = function getClientCredentials(provider) {
  const BaseOauthToken = provider.OAuthToken;
  return class ClientCredentials extends BaseOauthToken {};
};
