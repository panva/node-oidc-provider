import omitBy from './_/omit_by.js';

export default function appendWWWAuthenticate(ctx, scheme, fields) {
  const parameters = Object.entries(omitBy(fields, (v) => v === undefined))
    .map(([key, val]) => `${key}="${val.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(', ');

  ctx.append('WWW-Authenticate', `${scheme} ${parameters}`);
}
