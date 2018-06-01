const setAudiences = require('./mixins/set_audiences');

module.exports = function getAccessToken({ BaseToken }) {
  return class AccessToken extends setAudiences(BaseToken) {};
};
