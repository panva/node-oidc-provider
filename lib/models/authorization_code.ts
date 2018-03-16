export default function getAuthorizationCode({ BaseToken }) {
  return class AuthorizationCode extends BaseToken {};
};
