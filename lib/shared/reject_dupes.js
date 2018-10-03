const { InvalidRequest } = require('../helpers/errors');

function exceptMap([key, value]) {
  if (Array.isArray(value) && !this.has(key)) {
    return key;
  }
  return undefined;
}

function onlyMap([key, value]) {
  if (Array.isArray(value) && this.has(key)) {
    return key;
  }
  return undefined;
}

function defaultMap([key, value]) {
  return Array.isArray(value) ? key : undefined;
}

async function rejectDupes(ctx, next) {
  const { except, only } = this;

  let mapFn;

  if (except) {
    mapFn = exceptMap.bind(except);
  } else if (only) {
    mapFn = onlyMap.bind(only);
  } else {
    mapFn = defaultMap;
  }

  const dupes = Object.entries(ctx.oidc.params).map(mapFn);

  if (dupes.some(Boolean)) {
    const params = dupes.filter(Boolean);
    params.forEach((param) => {
      ctx.oidc.params[param] = undefined;
    });
    throw new InvalidRequest(`parameters must not be provided twice. (${params.join(',')})`);
  }

  await next();
}

module.exports = rejectDupes.bind({});
module.exports.only = only => rejectDupes.bind({ only });
module.exports.except = (except, ctx, next) => rejectDupes.call({ except }, ctx, next);
