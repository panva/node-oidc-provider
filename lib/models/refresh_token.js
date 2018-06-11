const storesAuth = require('./mixins/stores_auth');

module.exports = function getRefreshToken({ BaseToken }) {
  return class RefreshToken extends storesAuth(BaseToken) {};
};
