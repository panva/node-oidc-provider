const { WebMessageUriMismatch } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Checks that provided web_message_uri is whitelisted by the client configuration
 *
 * @throws: web_message_uri_mismatch
 */
module.exports = provider => async function checkWebMessageUri(ctx, next) {
  const { oidc } = ctx;
  const { client, params } = oidc;

  if (instance(provider).configuration('features.webMessageResponseMode')) {
    if (params.web_message_uri && !client.webMessageUriAllowed(params.web_message_uri)) {
      throw new WebMessageUriMismatch();
    } else {
      oidc.webMessageUriCheckPerformed = true;
    }
  }

  await next();
};
