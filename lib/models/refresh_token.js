'use strict';

module.exports = function getRefreshToken(BaseOauthToken) {
  return class RefreshToken extends BaseOauthToken {};
};
