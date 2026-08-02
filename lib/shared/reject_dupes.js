import { InvalidRequest } from '../helpers/errors.js';
import * as formatters from '../helpers/formatters.js';

export default function rejectDupes({ except, only } = {}, ctx, next) {
  const params = [];

  for (const [key, value] of Object.entries(ctx.oidc.params)) {
    if (!Array.isArray(value)) {
      continue;
    }

    if (except ? except.has(key) : only && !only.has(key)) {
      continue;
    }

    params.push(key);
    ctx.oidc.params[key] = undefined;
  }

  if (params.length) {
    throw new InvalidRequest(`${formatters.formatList(params)} ${formatters.pluralize('parameter', params.length)} must not be provided twice`);
  }

  return next();
}
