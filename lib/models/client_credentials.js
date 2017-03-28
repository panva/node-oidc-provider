module.exports = function getClientCredentials({ BaseToken }) {
  return class ClientCredentials extends BaseToken {};
};
