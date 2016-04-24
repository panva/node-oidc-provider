'use strict';

module.exports = function getAuthorizationCode(BaseOauthToken) {
  return class AuthorizationCode extends BaseOauthToken {};
};
