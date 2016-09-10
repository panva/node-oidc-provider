'use strict';

const bootstrap = require('../test_helper');

const route = '/.well-known/webfinger';

describe(route, function () {
  const { agent, provider } = bootstrap(__dirname);
  it('responds with jrd+json 200', function () {
    return agent.get(route)
      .expect('Content-Type', /application\/jrd\+json/)
      .expect(200);
  });

  it('returns the webfinger structure', function () {
    return agent.get(route)
      .query({
        resource: 'acct:joe@example.com'
      })
      .expect(200, {
        subject: 'acct:joe@example.com',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: provider.issuer
          }
        ]
      });
  });
});
