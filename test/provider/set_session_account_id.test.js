const { expect } = require('chai');

const bootstrap = require('../test_helper');
const epochTime = require('../../lib/helpers/epoch_time');

describe('provider.setProviderSession', () => {
  before(bootstrap(__dirname, { config: 'set_session' }));

  beforeEach(function () { return this.logout(); });

  it('sets the session id for a clear session with current timestamp', async function () {
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
      .expect(auth.validateInteractionError('consent_required', 'client_not_authorized'))
      .expect(() => {
        const session = this.getSession();
        expect(session).to.have.property('account', 'foo');
        expect(session).to.have.property('loginTs').that.is.closeTo(epochTime(), 1);
      });
  });

  it('sets the session id for an existing session', async function () {
    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login/foo') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo' });
      }
      if (ctx.path === '/login/bar') {
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'bar' });
      }
      await next();
    });

    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
    });

    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(auth.validateInteractionRedirect)
      .expect(auth.validateInteractionError('login_required', 'no_session'));

    const sessionId = this.getSessionId();

    await this.agent.post('/login/foo');
    expect(this.getSession()).to.have.property('account', 'foo');
    await this.agent.post('/login/bar');

    return this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(auth.validateInteractionRedirect)
      .expect(auth.validateInteractionError('consent_required', 'client_not_authorized'))
      .expect(() => {
        expect(this.getSessionId()).to.eql(sessionId);
        expect(this.getSession()).to.have.property('account', 'bar');
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

    const session = this.getSession();
    expect(session).to.have.nested.property('authorizations.foo').that.is.an('object');
    expect(session).to.have.nested.property('authorizations.bar').that.is.an('object');
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
        await this.provider.setProviderSession(ctx.req, ctx.res, { account: 'foo', meta });
      }
      await next();
    });

    try {
      await this.agent.post('/login');
    } catch (err) {
      expect(err.message).to.have.property('message', 'meta client_id must be in clients');
    }
  });
});
