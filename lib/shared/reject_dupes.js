const { InvalidRequest } = require('../helpers/errors');
const formatters = require('../helpers/formatters');

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

module.exports = function rejectDupes({ except, only } = {}, ctx, next) {
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
    throw new InvalidRequest(`${formatters.formatList(params)} ${formatters.pluralize('parameter', params.length)} must not be provided twice`);
  }

  return next();
};
