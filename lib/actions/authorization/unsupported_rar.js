import { InvalidRequest } from '../../helpers/errors.js';

export default async function unsupportedRar(ctx, next) {
  if (ctx.oidc.params.authorization_details !== undefined) {
    throw new InvalidRequest(`authorization_details is unsupported at the ${ctx.oidc.route}_endpoint`);
  }

  return next();
}
