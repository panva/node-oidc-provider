const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

function failWith(code, error, error_description, scope) {
  return ({ status, body, headers: { 'www-authenticate': wwwAuth } }) => {
    const { provider: { issuer } } = this;
    expect(status).to.eql(code);
    expect(body).to.have.property('error', error);
    expect(body).to.have.property('error_description', error_description);
    expect(wwwAuth).to.match(new RegExp(`^Bearer realm="${issuer}"`));
    expect(wwwAuth).to.match(new RegExp(`error="${error}"`));
    if (scope) expect(wwwAuth).to.match(new RegExp(`scope="${scope}"`));
  };
}

describe('userinfo /me', () => {
  before(bootstrap(__dirname));

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
      .expect(failWith.call(this, 401, 'invalid_token', 'invalid token provided'));
  });

  it('validates a client is still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({ clientId: 'client' }).save();
    sinon.stub(this.provider.Client, 'find').callsFake(async () => undefined);
    return this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(() => {
        this.provider.Client.find.restore();
      })
      .expect(failWith.call(this, 401, 'invalid_token', 'invalid token provided'));
  });

  it('validates an account still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({ clientId: 'client', accountId: 'notfound' }).save();
    return this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(failWith.call(this, 401, 'invalid_token', 'invalid token provided'));
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
      .expect(failWith.call(this, 400, 'invalid_scope', 'access token missing requested scope', 'profile'));
  });
});
