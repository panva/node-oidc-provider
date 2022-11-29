import { WebMessageUriMismatch } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Checks that provided web_message_uri is allowed in the client configuration
 *
 * @throws: web_message_uri_mismatch
 */
export default function checkWebMessageUri(ctx, next) {
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
}
