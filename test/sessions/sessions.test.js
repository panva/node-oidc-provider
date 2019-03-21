const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');
const epochTime = require('../../lib/helpers/epoch_time');

const route = '/auth';
const response_type = 'code';
const scope = 'openid';
const verb = 'get';

describe('session exp handling', () => {
  before(bootstrap(__dirname));

  afterEach(function () {
    try {
      this.TestAdapter.for('Session').destroy.restore();
    } catch (err) {}
  });
  afterEach(function () { return this.logout(); });

  it('generates a new session id when an expired session is found by the adapter', async function () {
    await this.login();
    const session = this.getSession();
    const oldSessionId = this.getSessionId();
    session.exp = epochTime();

    sinon.spy(this.TestAdapter.for('Session'), 'destroy');

    const auth = new this.AuthorizationRequest({
      response_type,
      scope,
    });

    await this.wrap({ route, verb, auth })
      .expect(302)
      .expect(auth.validateInteractionRedirect)
      .expect(auth.validateInteraction('login', 'no_session'));

    const newSessionId = this.getSessionId();
    expect(newSessionId).to.be.ok;
    expect(newSessionId).not.to.equal(oldSessionId);
  });

  describe('clockTolerance', () => {
    afterEach(function () {
      i(this.provider).configuration().clockTolerance = 0;
    });

    it('respects clockTolerance option', async function () {
      await this.login();
      const session = this.getSession();
      i(this.provider).configuration().clockTolerance = 10;
      session.exp = epochTime() - 5;

      sinon.spy(this.TestAdapter.for('Session'), 'destroy');

      const auth = new this.AuthorizationRequest({
        response_type,
        scope,
      });

      await this.wrap({ route, verb, auth })
        .expect(302)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);

      expect(this.TestAdapter.for('Session').destroy.called).to.be.false;
    });

    it('generates a new session id when an expired session is found by the adapter', async function () {
      await this.login();
      const session = this.getSession();
      i(this.provider).configuration().clockTolerance = 10;
      session.exp = epochTime() - 10;
      const oldSessionId = this.getSessionId();

      sinon.spy(this.TestAdapter.for('Session'), 'destroy');

      const auth = new this.AuthorizationRequest({
        response_type,
        scope,
      });

      await this.wrap({ route, verb, auth })
        .expect(302)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('login', 'no_session'));

      const newSessionId = this.getSessionId();
      expect(newSessionId).to.be.ok;
      expect(newSessionId).not.to.equal(oldSessionId);
    });
  });
});
