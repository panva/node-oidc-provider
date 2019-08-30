const presence = require('../../helpers/validate_presence');

/*
 * Ignores all parameters but `request` during `request_object_endpoint` calls
 *
 * @throws: invalid_request
 */
module.exports = function requestObjectEndpointParameters(ctx, next) {
  presence(ctx, 'request');
  Object.assign(
    ctx.oidc.params,
    Object.entries(ctx.oidc.params)
      .reduce((acc, [key, value]) => {
        acc[key] = key === 'request' ? value : undefined;
        return acc;
      }, {}),
  );

  return next();
};
