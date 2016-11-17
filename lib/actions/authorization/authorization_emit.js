'use strict';

module.exports = provider => async function authorizationEmit(ctx, next) {
  if (ctx.oidc.result) {
    provider.emit('interaction.ended', ctx);
  } else {
    provider.emit('authorization.accepted', ctx);
  }
  await next();
};
