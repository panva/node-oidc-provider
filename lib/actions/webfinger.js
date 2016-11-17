'use strict';

module.exports = function webfingerAction(provider) {
  return async function renderWebfingerResponse(ctx, next) {
    ctx.body = {
      links: [{
        href: provider.issuer,
        rel: 'http://openid.net/specs/connect/1.0/issuer',
      }],
      subject: ctx.query.resource,
    };
    ctx.type = 'application/jrd+json';
    await next();
  };
};
