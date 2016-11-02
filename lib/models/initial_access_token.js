'use strict';

module.exports = function getInitialAccessToken(provider) {
  const BaseToken = provider.BaseToken;
  return class InitialAccessToken extends BaseToken {};
};
