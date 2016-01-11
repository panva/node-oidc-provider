'use strict';

module.exports = function (BaseOauthToken) {
  return class AccessToken extends BaseOauthToken {};
};
