const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');

const { Provider } = require('../../lib');
const bootstrap = require('../test_helper');

describe('userinfo /me', () => {
  before(bootstrap(__dirname));

  before(function () { return this.login({ scope: 'openid email', rejectedClaims: ['email_verified'] }); });

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

  it('jwtUserinfo can only be enabled with userinfo', () => {
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          jwtUserinfo: { enabled: true },
          userinfo: { enabled: false },
        },
      });
    }).to.throw('jwtUserinfo is only available in conjuction with userinfo');
  });

  it('[get] returns 200 OK and user claims except the rejected ones', function () {
    return this.agent.get('/me')
      .auth(this.access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.keys(['sub', 'email']);
        expect(response.body).not.to.have.keys(['email_verified']);
      });
  });

  it('[post] returns 200 OK and user claims except the rejected ones', function () {
    return this.agent.post('/me')
      .auth(this.access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.keys(['sub', 'email']);
        expect(response.body).not.to.have.keys(['email_verified']);
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
      .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
  });

  it('validates access token is provided', function () {
    return this.agent.get('/me')
      .expect(this.failWith(400, 'invalid_request', 'no access token provided'));
  });

  it('validates a client is still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({ clientId: 'client' }).save();
    sinon.stub(this.provider.Client, 'find').callsFake(async () => undefined);
    return this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(() => {
        this.provider.Client.find.restore();
      })
      .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
  });

  it('validates an account still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({ clientId: 'client', accountId: 'notfound' }).save();
    return this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
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
      .expect(this.failWith(400, 'invalid_scope', 'access token missing requested scope', 'profile'));
  });
});
