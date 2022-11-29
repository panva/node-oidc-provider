import omitBy from './_/omit_by.js';

export default function setWWWAuthenticate(ctx, scheme, fields) {
  const wwwAuth = Object.entries(omitBy(fields, (v) => v === undefined))
    .map(([key, val]) => `${key}="${val.replace(/"/g, '\\"')}"`)
    .join(', ');

  ctx.set('WWW-Authenticate', `${scheme} ${wwwAuth}`);
}
