'use strict';

const getContext = require('../helpers/oidc_context');

module.exports = function getContextEnsureOidc(provider) {
  const OIDCContext = getContext(provider);
  return function* contextEnsureOidc(next) {
    Object.defineProperty(this, 'oidc', { value: new OIDCContext(this) });
    yield next;
  };
};
