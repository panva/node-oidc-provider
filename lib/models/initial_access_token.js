const hasFormat = require('./mixins/has_format');

module.exports = function getInitialAccessToken(provider) {
  return class InitialAccessToken extends hasFormat(provider, 'InitialAccessToken', provider.BaseToken) {
    static get IN_PAYLOAD() {
      return [
        'jti',
        'kind',
      ];
    }
  };
};
