'use strict';

const getContext = require('../helpers/oidc_context');

module.exports = function getContextEnsureOidc(provider) {
  const OIDCContext = getContext(provider);
  return async function contextEnsureOidc(ctx, next) {
    Object.defineProperty(ctx, 'oidc', { value: new OIDCContext(ctx) });
    await next();
  };
};
