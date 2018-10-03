const { URL } = require('url');

const instance = require('../helpers/weak_cache');
const { InvalidResource } = require('../helpers/errors');

module.exports = function getCheckResource(provider) {
  return function checkResource({ oidc: { params } }, next) {
    if (!instance(provider).configuration('features.resourceIndicators') || params.resource === undefined) {
      return next();
    }

    let requested = params.resource;
    if (!Array.isArray(requested)) {
      requested = [requested];
    }

    requested.forEach((resource) => {
      let href;
      try {
        ({ href } = new URL(resource)); // eslint-disable-line no-new
      } catch (err) {
        throw new InvalidResource('resource must be an absolute URI');
      }

      // NOTE: we don't check for new URL() => search of hash because of an edge case
      // new URL('https://example.com?#') => they're empty, seems like an inconsistent validation
      if (href.includes('#')) {
        throw new InvalidResource('resource must not contain a fragment component');
      }

      if (href.includes('?')) {
        throw new InvalidResource('resource must not contain a query component');
      }
    });

    return next();
  };
};
