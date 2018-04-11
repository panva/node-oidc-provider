const bootstrap = require('../test_helper');
const { expect } = require('chai');

describe('provider.setProviderSession(req, res, id)', () => {
  before(bootstrap(__dirname, 'set_session'));

  beforeEach(function () { return this.logout(); });

  it('sets the session id for a clear session', async function () {
    // simulates setting a fresh session (non existant) in another request
    const ts = 1523457660;
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login') {
        await this.provider.setProviderSession(ctx.req, ctx.res, 'foo', ts);
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
        expect(session).to.have.property('loginTs', ts);
      });
  });

  it('sets the session id for an existing session', async function () {
    // simulates setting a fresh session (non existant) in another request
    this.provider.use(async (ctx, next) => {
      if (ctx.path === '/login/foo') {
        await this.provider.setProviderSession(ctx.req, ctx.res, 'foo');
      }
      if (ctx.path === '/login/bar') {
        await this.provider.setProviderSession(ctx.req, ctx.res, 'bar');
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
});
