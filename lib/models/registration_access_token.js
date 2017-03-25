module.exports = function getRegistrationAccessToken(provider) {
  const BaseToken = provider.BaseToken;
  return class RegistrationAccessToken extends BaseToken {};
};
