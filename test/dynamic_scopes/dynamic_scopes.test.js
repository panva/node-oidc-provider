const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

const scope = 'openid sign:70616e7661';

describe('dynamic scopes', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login({ scope }); });

  it('do not show up in discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect(({ body }) => {
        expect(body).to.have.property('scopes_supported').to.eql(['openid', 'offline_access', 'address', 'email', 'phone', 'profile']);
      });
  });

  describe('client credentials', () => {
    it('allows dynamic scopes to be requested and returned by client credentials', async function () {
      const spy = sinon.spy();
      this.provider.once('token.issued', spy);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          scope: 'sign:70616e7661',
          grant_type: 'client_credentials',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('scope', 'sign:70616e7661');
        });

      const [[token]] = spy.args;

      expect(token).to.have.property('scope', 'sign:70616e7661');
    });
  });

  describe('authorization', () => {
    it('allows dynamic scopes to be requested and added to token scopes', async function () {
      const spy = sinon.spy();
      this.provider.on('token.issued', spy);

      const auth = new this.AuthorizationRequest({
        response_type: 'code token',
        scope,
      });

      let accessToken;
      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          ({ query: { access_token: accessToken } } = url.parse(location, true));
        })
        .catch((err) => {
          this.provider.removeAllListeners('token.issued');
          throw err;
        });

      const [[code], [token]] = spy.args;

      expect(code).to.have.property('scope', scope);
      expect(token).to.have.property('scope', scope);

      await this.agent.get('/me')
        .auth(accessToken, { type: 'bearer' })
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('updated_at');
        });
    });
  });
});
