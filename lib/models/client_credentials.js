module.exports = function getClientCredentials(provider) {
  const BaseToken = provider.BaseToken;
  return class ClientCredentials extends BaseToken {};
};
