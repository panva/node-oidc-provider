'use strict';

module.exports = function(BaseOauthToken) {
  return class ClientCredentials extends BaseOauthToken {};
};
