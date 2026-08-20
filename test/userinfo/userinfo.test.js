import * as url from 'node:url';

import { expect } from 'chai';
import sinon from 'sinon';

import Provider from '../../lib/index.js';
import bootstrap from '../test_helper.js';

describe('userinfo /me', () => {
  before(bootstrap(import.meta.url));

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
      new Provider('http://localhost', {
        features: {
          jwtUserinfo: { enabled: true },
          userinfo: { enabled: false },
        },
      });
    }).to.throw('jwtUserinfo is only available in conjunction with userinfo');
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
    this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Client', 'Grant', 'AccessToken', 'Account');
      expect(Object.keys(ctx.oidc.entities)).to.deep.equal([
        'AccessToken',
        'Client',
        'Account',
        'Grant',
      ]);
    }, done);

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
      .expect(this.failWith(401, 'invalid_token', 'no access token provided'));
  });

  it('validates the openid scope is present', async function () {
    const at = await new this.provider.AccessToken({
      client: await this.provider.Client.find('client'),
    }).save();
    sinon.stub(this.provider.Client, 'find').callsFake(async () => undefined);
    return this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(() => {
        this.provider.Client.find.restore();
      })
      .expect(this.failWith(403, 'insufficient_scope', 'access token missing openid scope', 'openid'));
  });

  it('validates a client is still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({
      client: await this.provider.Client.find('client'),
      scope: 'openid',
    }).save();
    const find = sinon.stub(this.provider.Client, 'find').resolves();
    const spy = sinon.spy();
    this.provider.once('userinfo.error', spy);

    try {
      await this.agent.get('/me')
        .auth(at, { type: 'bearer' })
        .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
    } finally {
      find.restore();
    }

    expect(spy).to.have.property('calledOnce', true);
    expect(spy.args[0][1]).to.have.property('error_detail', 'associated client not found');
    expect(Object.keys(spy.args[0][0].oidc.entities)).to.deep.equal(['AccessToken']);
  });

  it('validates an account still valid for a found token', async function () {
    const at = await new this.provider.AccessToken({
      client: await this.provider.Client.find('client'),
      scope: 'openid',
      accountId: 'notfound',
    }).save();
    const spy = sinon.spy();
    this.provider.once('userinfo.error', spy);

    await this.agent.get('/me')
      .auth(at, { type: 'bearer' })
      .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));

    expect(spy).to.have.property('calledOnce', true);
    expect(spy.args[0][1]).to.have.property('error_detail', 'associated account not found');
    expect(Object.keys(spy.args[0][0].oidc.entities)).to.deep.equal([
      'AccessToken',
      'Client',
    ]);
  });

  for (const { title, getGrant, errorDetail } of [
    {
      title: 'validates the associated grant is found',
      getGrant() {},
      errorDetail: 'grant not found',
    },
    {
      title: 'validates the associated grant is not expired',
      getGrant(accessToken) {
        return {
          isExpired: true,
          clientId: accessToken.clientId,
          accountId: accessToken.accountId,
        };
      },
      errorDetail: 'grant is expired',
    },
    {
      title: 'validates the associated grant belongs to the client',
      getGrant(accessToken) {
        return {
          isExpired: false,
          clientId: 'another-client',
          accountId: accessToken.accountId,
        };
      },
      errorDetail: 'clientId mismatch',
    },
    {
      title: 'validates the associated grant belongs to the account',
      getGrant(accessToken) {
        return {
          isExpired: false,
          clientId: accessToken.clientId,
          accountId: 'another-account',
        };
      },
      errorDetail: 'accountId mismatch',
    },
  ]) {
    it(title, async function () {
      const accessToken = await this.provider.AccessToken.find(this.access_token);
      const find = sinon.stub(this.provider.Grant, 'find').resolves(getGrant(accessToken));
      const spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      try {
        await this.agent.get('/me')
          .auth(this.access_token, { type: 'bearer' })
          .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
      } finally {
        find.restore();
      }

      expect(find.calledOnceWithExactly(accessToken.grantId, {
        ignoreExpiration: true,
      })).to.be.true;
      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', errorDetail);
      expect(Object.keys(spy.args[0][0].oidc.entities)).to.deep.equal([
        'AccessToken',
        'Client',
        'Account',
      ]);
    });
  }

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
      .expect(this.failWith(403, 'insufficient_scope', 'access token missing requested scope', 'profile'));
  });

  it('rejects control characters in a requested scope without failing header serialization', function () {
    return this.agent.get('/me')
      .query({
        scope: 'openid profile\ninjected',
      })
      .auth(this.access_token, { type: 'bearer' })
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: 'scope contains invalid characters',
      });
  });
});
