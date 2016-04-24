'use strict';

module.exports = function getClientCredentials(BaseOauthToken) {
  return class ClientCredentials extends BaseOauthToken {};
};
