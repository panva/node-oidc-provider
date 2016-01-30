'use strict';

module.exports = function(BaseOauthToken) {
  return class RefreshToken extends BaseOauthToken {};
};
