'use strict';

module.exports = function(BaseOauthToken) {
  return class AuthorizationCode extends BaseOauthToken {};
};
