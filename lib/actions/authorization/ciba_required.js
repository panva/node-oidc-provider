import presence from '../../helpers/validate_presence.js';
import { InvalidRequest } from '../../helpers/errors.js';

const CLIENT_NOTIFICATION_TOKEN = /^[A-Za-z0-9._~+\x2F-]+=*$/u;

export default function cibaRequired(ctx, next) {
  const required = new Set(['scope']);
  const callbackMode = ctx.oidc.client.backchannelTokenDeliveryMode !== 'poll';

  if (callbackMode) {
    required.add('client_notification_token');
  }

  presence(ctx, ...required);

  if (callbackMode) {
    const { client_notification_token: clientNotificationToken } = ctx.oidc.params;
    if (!CLIENT_NOTIFICATION_TOKEN.test(clientNotificationToken)) {
      throw new InvalidRequest('client_notification_token must be a valid Bearer token');
    }

    if (clientNotificationToken.length > 1024) {
      throw new InvalidRequest('client_notification_token must not exceed 1024 characters');
    }
  } else {
    ctx.oidc.params.client_notification_token = undefined;
  }

  return next();
}
