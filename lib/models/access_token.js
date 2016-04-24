'use strict';

module.exports = function getAccessToken(BaseOauthToken) {
  return class AccessToken extends BaseOauthToken {};
};
