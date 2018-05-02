const setAudiences = require('./mixins/set_audiences');

module.exports = function getClientCredentials({ BaseToken }) {
  return class ClientCredentials extends setAudiences(BaseToken) {};
};
