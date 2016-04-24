'use strict';

module.exports = function webfingerAction(provider) {
  return function * renderWebfingerResponse(next) {
    this.body = {
      links: [{
        href: provider.issuer,
        rel: 'http://openid.net/specs/connect/1.0/issuer',
      }],
      subject: this.query.resource,
    };
    this.type = 'application/jrd+json';
    yield next;
  };
};
