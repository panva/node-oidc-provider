import * as formatters from './formatters.js';
import { InvalidRequest } from './errors.js';

export default function validatePresence(ctx, ...required) {
  const { params } = ctx.oidc;
  const missing = required.map((param) => {
    if (params[param] === undefined) {
      return param;
    }

    return undefined;
  }).filter(Boolean);

  if (missing.length) {
    throw new InvalidRequest(`missing required ${formatters.pluralize('parameter', missing.length)} ${formatters.formatList(missing)}`);
  }
}
