module.exports = function getAuthorizationCode(provider) {
  const BaseToken = provider.BaseToken;
  return class AuthorizationCode extends BaseToken {};
};
