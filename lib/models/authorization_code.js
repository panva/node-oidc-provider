module.exports = function getAuthorizationCode({ BaseToken }) {
  return class AuthorizationCode extends BaseToken {};
};
