const { expect } = require('chai');

const bootstrap = require('../test_helper');
const epochTime = require('../../lib/helpers/epoch_time');

describe('provider.setProviderSession', () => {
  before(bootstrap(__dirname, { config: 'set_session' }));

  beforeEach(function () { return this.logout(); });

  it('sets the session id for a clear session with current timestamp', async function () {
    this.retries(1);

    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo' });
      }
      await next();
    });

    expect(() => {
      this.getSession();
    }).to.throw();

    await this.agent.post('/login');

    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
    });

    return this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(auth.validateInteractionRedirect)
      .expect(auth.validateInteraction('consent', 'client_not_authorized'))
      .expect(() => {
        const session = this.getSession();
        expect(session).to.have.property('account', 'foo');
        expect(session).to.have.property('loginTs').that.is.closeTo(epochTime(), 1);
      });
  });

  it('sets the already authorized clients', async function () {
    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo', clients: ['foo', 'bar'] });
      }
      await next();
    });

    await this.agent.post('/login');

    const session = this.getSession({ instantiate: true });
    expect(session).to.have.nested.property('authorizations.foo').that.is.an('object');
    expect(session).to.have.nested.property('authorizations.bar').that.is.an('object');
    expect(session.sidFor('foo')).to.be.ok;
    expect(session.sidFor('bar')).to.be.ok;
    expect(session.acceptedScopesFor('foo')).to.be.empty;
    expect(session.acceptedScopesFor('bar')).to.be.empty;
    expect(session.acceptedClaimsFor('foo')).to.be.empty;
    expect(session.acceptedClaimsFor('bar')).to.be.empty;
  });

  it('sets the session as persistent by default', async function () {
    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo' });
      }
      await next();
    });

    await this.agent.post('/login');

    const { expiration_date } = this.agent.jar.getCookie('_session', { path: '/' });
    expect(expiration_date).not.to.eql(Infinity);

    const session = this.getSession();
    expect(session).not.to.have.property('transient');
  });

  it('sets the session as transient when requested', async function () {
    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo', remember: false });
      }
      await next();
    });

    await this.agent.post('/login');

    const { expiration_date } = this.agent.jar.getCookie('_session', { path: '/' });
    expect(expiration_date).to.eql(Infinity);

    const session = this.getSession();
    expect(session).to.have.property('transient', true);
  });

  it("sets the session's loginTs", async function () {
    // simulates setting a fresh session (non existant) in another request
    const ts = 1523457660;
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo', ts });
      }
      await next();
    });

    await this.agent.post('/login');
    const session = this.getSession();
    expect(session).to.have.property('loginTs', ts);
  });

  it("sets the session's meta", async function () {
    const meta = {
      mywebsite: { error: 'password-expired' },
    };

    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo', clients: ['mywebsite'], meta });
      }
      await next();
    });

    await this.agent.post('/login');
    const session = this.getSession();
    expect(session).to.have.nested.property('authorizations.mywebsite').that.is.an('object');
  });

  it("setting the session's meta fails when client not found in clients array", async function () {
    const meta = {
      'client-1': { error: 'password-expired' },
    };

    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        try {
          await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo', meta });
          throw new Error('expected failure in this.provider.setProviderSession');
        } catch (err) {
          expect(err).to.have.property('message', 'meta client_id must be in clients');
        }
      }

      await next();
    });

    await this.agent.post('/login');
  });
});
