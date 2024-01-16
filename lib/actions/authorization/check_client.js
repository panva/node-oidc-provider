import presence from '../../helpers/validate_presence.js';
import { InvalidClient } from '../../helpers/errors.js';

/*
 * Checks client_id
 */
export default async function checkClient(ctx, next) {
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
