const { InvalidRequest } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');

module.exports = async function checkParams(ctx, next) {
  presence(ctx, 'scope');

  const scopes = ctx.oidc.params.scope.split(' ');
  if (!scopes.includes('openid')) {
    throw new InvalidRequest('openid is required scope');
  }

  await next();
};
