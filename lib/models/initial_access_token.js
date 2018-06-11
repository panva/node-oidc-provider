module.exports = function getInitialAccessToken({ BaseToken }) {
  return class InitialAccessToken extends BaseToken {
    static get IN_PAYLOAD() {
      return [
        'jti',
        'kind',
      ];
    }
  };
};
