import presence from '../../helpers/validate_presence.js';
import { InvalidClient, InvalidRequest } from '../../helpers/errors.js';

function deviceAuthorizationResponse(ctx, next) {
  if (!ctx.oidc.body.client_id) {
    ctx.oidc.body.client_id = ctx.oidc.client.clientId;
  }
  return next();
}

/*
 * Checks client_id
 */
export async function checkClient(ctx, next) {
  presence(ctx, 'client_id');

  const client = await ctx.oidc.provider.Client.find(ctx.oidc.params.client_id);

  if (!client) {
    // there's no point in checking again in authorization error handler
    ctx.oidc.noclient = true;
    throw new InvalidClient('client is invalid', 'client not found');
  }

  ctx.oidc.entity('Client', client);

  return next();
}

export function checkClientGrantType({ oidc: { route, client } }, next) {
  let grantType;
  switch (route) {
    case 'device_authorization':
      grantType = 'urn:ietf:params:oauth:grant-type:device_code';
      break;
    case 'backchannel_authentication':
      grantType = 'urn:openid:params:grant-type:ciba';
      break;
    default:
      throw new Error('not implemented');
  }

  if (!client.grantTypeAllowed(grantType)) {
    throw new InvalidRequest(`${grantType} is not allowed for this client`);
  }

  return next();
}

export { deviceAuthorizationResponse as authenticatedClientId };
