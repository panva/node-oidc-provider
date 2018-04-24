const bootstrap = require('../test_helper');
const { expect } = require('chai');

const route = '/.well-known/webfinger';

describe(route, () => {
  before(bootstrap(__dirname)); // agent, provider
  it('responds with jrd+json 200', function () {
    return this.agent.get(route)
      .expect('Content-Type', /application\/jrd\+json/)
      .expect(200);
  });

  it('returns the webfinger structure', function () {
    return this.agent.get(route)
      .query({
        resource: 'acct:joe@example.com',
      })
      .expect(200)
      .expect({
        subject: 'acct:joe@example.com',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: this.provider.issuer,
          },
        ],
      });
  });

  it('does not populate ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.be.empty;
    }, done));

    this.agent.get(route)
      .query({
        resource: 'acct:joe@example.com',
      })
      .end(() => {});
  });
});
