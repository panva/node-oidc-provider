import * as crypto from 'node:crypto';

import { InvalidRequest } from '../helpers/errors.js';
import constantEquals from '../helpers/constant_equals.js';

export function generateXsrf(ctx, next) {
  const secret = crypto.randomBytes(24).toString('hex');
  ctx.oidc.session.state = { secret };
  return next();
}

export function checkXsrf(missingMessage) {
  return async function verifyXsrf(ctx, next) {
    if (!ctx.oidc.session.state) {
      throw new InvalidRequest(missingMessage);
    }
    if (!constantEquals(ctx.oidc.session.state.secret, ctx.oidc.params.xsrf || '')) {
      throw new InvalidRequest('xsrf token invalid');
    }
    await next();
  };
}
