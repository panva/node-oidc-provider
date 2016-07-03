'use strict';

module.exports = function getClientCredentials(provider) {
  const BaseOauthToken = provider.get('OAuthToken');
  return class ClientCredentials extends BaseOauthToken {};
};
