import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

const route = '/auth';
const response_type = 'code';
const scope = 'openid';
const verb = 'get';

describe('session exp handling', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => {
    try {
      fixture.TestAdapter.for('Session').destroy.restore();
    } catch {}
  }, { timeout: 3000 });
  afterEach(() => fixture.logout(), { timeout: 3000 });

  it('generates a new session id when an expired session is found by the adapter', { timeout: 3000 }, async () => {
    await fixture.login();
    const session = fixture.getSession();
    const oldSessionId = fixture.getSessionId();
    session.exp = epochTime() - 300;

    sinon.spy(fixture.TestAdapter.for('Session'), 'destroy');

    const auth = new fixture.AuthorizationRequest({
      response_type,
      scope,
    });

    await fixture.wrap({ route, verb, auth })
      .expect(303)
      .expect(auth.validateInteractionRedirect)
      .expect(auth.validateInteraction('login', 'no_session'));

    const newSessionId = fixture.getSessionId();
    assert.ok(newSessionId);
    assert.notEqual(newSessionId, oldSessionId);
  });

  describe('clockTolerance', () => {
    const fixture1 = Object.create(fixture);

    afterEach(() => {
      i(fixture1.provider).configuration.clockTolerance = 0;
    }, { timeout: 3000 });

    it('respects clockTolerance option', { timeout: 3000 }, async () => {
      await fixture1.login();
      const session = fixture1.getSession();
      i(fixture1.provider).configuration.clockTolerance = 10;
      session.exp = epochTime() - 5;

      sinon.spy(fixture1.TestAdapter.for('Session'), 'destroy');

      const auth = new fixture1.AuthorizationRequest({
        response_type,
        scope,
      });

      await fixture1.wrap({ route, verb, auth })
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);

      assert.equal(fixture1.TestAdapter.for('Session').destroy.called, false);
    });

    it('generates a new session id when an expired session is found by the adapter', { timeout: 3000 }, async () => {
      await fixture1.login();
      const session = fixture1.getSession();
      i(fixture1.provider).configuration.clockTolerance = 10;
      session.exp = epochTime() - 10;
      const oldSessionId = fixture1.getSessionId();

      sinon.spy(fixture1.TestAdapter.for('Session'), 'destroy');

      const auth = new fixture1.AuthorizationRequest({
        response_type,
        scope,
      });

      await fixture1.wrap({ route, verb, auth })
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('login', 'no_session'));

      const newSessionId = fixture1.getSessionId();
      assert.ok(newSessionId);
      assert.notEqual(newSessionId, oldSessionId);
    });
  });
});
