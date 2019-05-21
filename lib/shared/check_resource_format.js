const { URL } = require('url');

const instance = require('../helpers/weak_cache');
const { InvalidTarget } = require('../helpers/errors');

module.exports = function checkResourceFormat({ oidc: { params, provider } }, next) {
  if (!instance(provider).configuration('features.resourceIndicators') || params.resource === undefined) {
    return next();
  }

  let { resource: resources } = params;
  if (!Array.isArray(resources)) {
    resources = [resources];
  }

  resources.forEach((resource) => {
    let href;
    try {
      ({ href } = new URL(resource));
    } catch (err) {
      throw new InvalidTarget('resource must be an absolute URI');
    }

    // NOTE: we don't check for new URL() => search of hash because of an edge case
    // new URL('https://example.com?#') => search and hash are empty, seems like an inconsistent validation
    if (href.includes('#')) {
      throw new InvalidTarget('resource must not contain a fragment component');
    }
  });

  return next();
};
