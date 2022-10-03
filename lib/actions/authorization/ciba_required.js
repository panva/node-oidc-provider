const presence = require('../../helpers/validate_presence');

module.exports = function oidcRequired(ctx, next) {
  const required = new Set(['scope']);

  if (ctx.oidc.client.backchannelTokenDeliveryMode !== 'poll') {
    required.add('client_notification_token');
  }

  presence(ctx, ...required);

  return next();
};
