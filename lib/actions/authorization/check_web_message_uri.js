const { WebMessageUriMismatch } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Checks that provided web_message_uri is whitelisted by the client configuration
 *
 * @throws: web_message_uri_mismatch
 */
module.exports = function checkWebMessageUri(ctx, next) {
  const { oidc } = ctx;
  const { client, params } = oidc;

  if (instance(ctx.oidc.provider).configuration('features.webMessageResponseMode.enabled')) {
    if (params.web_message_uri && !client.webMessageUriAllowed(params.web_message_uri)) {
      throw new WebMessageUriMismatch();
    } else {
      oidc.webMessageUriCheckPerformed = true;
    }
  }

  return next();
};
