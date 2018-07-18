const presence = require('../../helpers/validate_presence');

const REQUIRED = [
  'response_type', 'scope',
];

/*
 * Validates presence of mandatory OAuth2.0 parameters response_type, client_id and scope.
 *
 * @throws: invalid_request
 */
module.exports = async function oauthRequired(ctx, next) {
  // Validate: required oauth params
  presence(ctx, ...REQUIRED);
  await next();
};
