const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');

const route = '/token';

describe('grant_type=client_credentials', () => {
  before(bootstrap(__dirname));

  it('provides a Bearer client credentials token', function () {
    const spy = sinon.spy();
    this.provider.once('grant.success', spy);

    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type', 'scope');
      });
  });

  it('ignores unsupported scopes', async function () {
    const spy = sinon.spy();
    this.provider.once('client_credentials.saved', spy);

    await this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:admin',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type', 'scope');
      });

    const [[token]] = spy.args;

    expect(token).to.have.property('scope', 'api:read');
  });

  it('checks clients scope whitelist', async function () {
    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:write',
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_scope',
        error_description: 'requested scope is not whitelisted',
        scope: 'api:write',
      });
  });

  it('populates ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Client', 'ClientCredentials');
    }, done));

    this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
      })
      .type('form')
      .end(() => {});
  });
});
