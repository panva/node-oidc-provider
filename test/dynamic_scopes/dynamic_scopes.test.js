const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

const scope = 'openid sign:70616e7661';

describe('dynamic scopes', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login({ scope }); });

  it('show up in discovery if they have a label', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect(({ body }) => {
        expect(body).to.have.property('scopes_supported').to.eql([
          'openid',
          'offline_access',
          'address',
          'email',
          'phone',
          'profile',
          'sign:{hex}',
          // read:{hex} is missing
        ]);
      });
  });

  describe('client credentials', () => {
    it('allows dynamic scopes to be requested and returned by client credentials', async function () {
      const spy = sinon.spy();
      this.provider.once('client_credentials.saved', spy);

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

    it('validates whitelisted dynamic scopes', async function () {
      const spy = sinon.spy();
      this.provider.once('authorization.error', spy);
      await this.agent.post('/token')
        .send({
          client_id: 'client-limited-scope',
          grant_type: 'client_credentials',
          scope: 'openid foobar sign:F0F0F0', // foobar is ignored, sign:{hex} is not whitelisted
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_scope',
          error_description: 'requested scope is not whitelisted',
          scope: 'sign:F0F0F0',
        });
    });
  });

  describe('authorization', () => {
    it('validates whitelisted dynamic scopes', function () {
      const spy = sinon.spy();
      this.provider.once('authorization.error', spy);
      const auth = new this.AuthorizationRequest({
        client_id: 'client-limited-scope',
        response_type: 'code',
        scope: 'openid foobar sign:F0F0F0', // foobar is ignored, sign:{hex} is not whitelisted
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect(auth.validatePresence(['error', 'error_description', 'state', 'scope']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_scope'))
        .expect(auth.validateScope('sign:F0F0F0'))
        .expect(auth.validateErrorDescription('requested scope is not whitelisted'));
    });

    it('allows dynamic scopes to be requested and added to token scopes', async function () {
      const spy = sinon.spy();
      this.provider.once('authorization_code.saved', spy);
      this.provider.once('access_token.saved', spy);

      const auth = new this.AuthorizationRequest({
        response_type: 'code token',
        scope,
      });

      let accessToken;
      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          ({ query: { access_token: accessToken } } = url.parse(location, true));
        })
        .catch((err) => {
          this.provider.removeAllListeners('authorization_code.saved');
          this.provider.removeAllListeners('access_token.saved');
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
