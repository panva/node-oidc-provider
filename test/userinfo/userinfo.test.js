const bootstrap = require('../test_helper');
const { expect } = require('chai');
const url = require('url');

describe('userinfo /me', () => {
  before(bootstrap(__dirname)); // this.provider, agent, this.AuthorizationRequest, wrap

  before(function () { return this.login(); });

  before(function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token token',
      scope: 'openid email',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect(auth.validateFragment)
      .expect((response) => {
        const { query } = url.parse(response.headers.location, true);
        this.access_token = query.access_token;
      });
  });

  it('returns 200 OK and user claims', function () {
    return this.agent.get('/me')
      .auth(this.access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.keys(['sub', 'email', 'email_verified']);
      });
  });

  it('populates ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Client', 'AccessToken', 'Account');
    }, done));

    (async () => {
      await this.agent.get('/me').auth(this.access_token, { type: 'bearer' });
    })().catch(done);
  });

  it('validates access token is found', function () {
    return this.agent.get('/me')
      .auth('Loremipsumdolorsitametconsecteturadipisicingelitsed', { type: 'bearer' })
      .expect(401)
      .expect({ error: 'invalid_token', error_description: 'invalid token provided' });
  });

  it('validates a client is still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({ clientId: 'notfound' }).save();
    return this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(401)
      .expect({ error: 'invalid_token', error_description: 'invalid token provided' });
  });

  it('validates an account still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({ clientId: 'client', accountId: 'notfound' }).save();
    return this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(401)
      .expect({ error: 'invalid_token', error_description: 'invalid token provided' });
  });

  it('does allow for scopes to be shrunk', function () {
    return this.agent.get('/me')
      .query({
        scope: 'openid',
      })
      .auth(this.access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.keys(['sub']);
        expect(response.body).not.to.have.keys(['email', 'email_verified']);
      });
  });

  it('does not allow for scopes to be extended', function () {
    return this.agent.get('/me')
      .query({
        scope: 'openid profile',
      })
      .auth(this.access_token, { type: 'bearer' })
      .expect(400)
      .expect({ error: 'invalid_scope', scope: 'profile', error_description: 'access token missing requested scope' });
  });

  describe('userinfo /me WWW-Authenticate header', () => {
    it('is set', function () {
      return this.agent.get('/me')
        .auth('ThisIsNotAValidToken', { type: 'bearer' })
        .expect(401)
        .expect('WWW-Authenticate', new RegExp(`^Bearer realm="${this.provider.issuer}"`))
        .expect('WWW-Authenticate', /error="invalid_token"/);
    });

    it('is set when html request', function () {
      return this.agent.get('/me')
        .accept('html')
        .query({ access_token: 'ThisIsNotAValidToken' })
        .expect(401)
        .expect('WWW-Authenticate', new RegExp(`^Bearer realm="${this.provider.issuer}"`))
        .expect('WWW-Authenticate', /error="invalid_token"/);
    });
  });
});
