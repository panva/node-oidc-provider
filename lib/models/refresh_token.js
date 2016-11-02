'use strict';

module.exports = function getRefreshToken(provider) {
  const BaseToken = provider.BaseToken;
  return class RefreshToken extends BaseToken {};
};
