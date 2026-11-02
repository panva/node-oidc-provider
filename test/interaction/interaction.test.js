import { it, describe, before, afterEach, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';

import { createSandbox } from 'sinon';

import nanoid from '../../lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

const sinon = createSandbox();

const expire = new Date();
expire.setDate(expire.getDate() + 1);
const expired = new Date(0);

function handlesInteractionSessionErrors(fixture) {
  it('"handles" not found interaction session id cookie', { timeout: 3000 }, async () => {
    const cookies = [
      `_interaction=; path=${fixture.url}; expires=${expired.toGMTString()}; httponly`,
    ];
    fixture.agent._saveCookies.bind(fixture.agent)({
      request: { url: fixture.provider.issuer },
      headers: { 'set-cookie': cookies },
    });

    sinon.spy(fixture.provider, 'interactionDetails');

    await fixture.agent.get(fixture.url).expect(400);
    return assert.rejects(fixture.provider.interactionDetails.getCall(0).returnValue, (err) => {
      assert.deepEqual(err.name, 'SessionNotFound');
      assert.deepEqual(err.error_description, 'interaction session id cookie not found');
      return true;
    });
  });

  it('"handles" not found interaction session', { timeout: 3000 }, async () => {
    sinon.stub(fixture.provider.Interaction, 'find').resolves();

    sinon.spy(fixture.provider, 'interactionDetails');

    await fixture.agent.get(fixture.url).expect(400);
    return assert.rejects(fixture.provider.interactionDetails.getCall(0).returnValue, (err) => {
      assert.deepEqual(err.name, 'SessionNotFound');
      assert.deepEqual(err.error_description, 'interaction session not found');
      return true;
    });
  });
}
describe('devInteractions', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  describe('render login', () => {
    const fixture1 = Object.create(fixture);

    beforeEach(() => fixture1.logout(), { timeout: 3000 });
    beforeEach(() => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .then((response) => {
          fixture1.url = response.headers.location;
        });
    }, { timeout: 3000 });

    it('with a form', { timeout: 3000 }, () => fixture1.agent.get(fixture1.url)
        .expect(200)
        .expect(new RegExp(`action="${fixture1.provider.issuer}${fixture1.url}"`))
        .expect(/name="prompt" value="login"/)
        .expect(/Sign-in/));

    handlesInteractionSessionErrors(fixture1);
  });

  describe('escapes debug output HTML', () => {
    const fixture2 = Object.create(fixture);

    beforeEach(() => fixture2.logout(), { timeout: 3000 });
    beforeEach(() => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        state: '<img src=x onerror=alert(1)>',
      });

      return fixture2.agent.get('/auth')
        .query(auth)
        .then((response) => {
          fixture2.url = response.headers.location;
        });
    }, { timeout: 3000 });

    it('HTML-escapes parameter values in the debug section', { timeout: 3000 }, () => fixture2.agent.get(fixture2.url)
        .expect(200)
        .expect((response) => {
          assert.doesNotMatch(response.text, /<img src=x onerror=alert\(1\)>/);
          assert.ok(response.text.includes('&lt;img src=x onerror=alert(1)&gt;'));
        }));
  });

  describe('render interaction', () => {
    const fixture3 = Object.create(fixture);

    beforeEach(() => fixture3.logout(), { timeout: 3000 });
    beforeEach(() => fixture3.login(), { timeout: 3000 });
    beforeEach(() => {
      const auth = new fixture3.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'consent',
      });

      return fixture3.agent.get('/auth')
        .query(auth)
        .then((response) => {
          fixture3.url = response.headers.location;
        });
    }, { timeout: 3000 });

    it('with a form', { timeout: 3000 }, () => fixture3.agent.get(fixture3.url)
        .expect(200)
        .expect(new RegExp(`action="${fixture3.provider.issuer}${fixture3.url}"`))
        .expect(/name="prompt" value="consent"/)
        .expect(/Authorize/));

    it('checks that the authentication session is still there', { timeout: 3000 }, async () => {
      const session = fixture3.getSession({ instantiate: true });
      await session.destroy();

      await fixture3.agent.get(fixture3.url)
        .accept('text/html')
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/session not found/);
    });

    it("checks that the authentication session's principal didn't change", { timeout: 3000 }, async () => {
      const session = fixture3.getSession({ instantiate: true });
      session.accountId = 'foobar';
      await session.persist();

      await fixture3.agent.get(fixture3.url)
        .accept('text/html')
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/session principal changed/);
    });
  });

  describe('when unimplemented prompt is requested', () => {
    const fixture4 = Object.create(fixture);

    beforeEach(() => fixture4.logout(), { timeout: 3000 });

    it('throws a 501', { timeout: 3000 }, async () => {
      const auth = new fixture4.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      const url = await fixture4.agent.get('/auth')
        .query(auth)
        .then((response) => response.headers.location);

      const split = url.split('/');
      const uid = split[split.length - 1];
      const interaction = fixture4.TestAdapter.for('Interaction').syncFind(uid);
      interaction.prompt.name = 'notimplemented';

      return fixture4.agent.get(url).expect(501);
    });
  });

  describe('navigate to abort', () => {
    const fixture5 = Object.create(fixture);

    before(() => fixture5.logout(), { timeout: 3000 });

    it('should abort an interaction with an error', { timeout: 3000 }, async () => {
      const auth = new fixture5.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await fixture5.agent.get('/auth')
        .query(auth)
        .then((response) => {
          fixture5.url = response.headers.location;
        });

      await fixture5.agent.get(`${fixture5.url}/abort`)
        .expect(303)
        .expect(({ headers: { location } }) => {
          fixture5.location = location;
        });

      return fixture5.agent.get(fixture5.url.replace('interaction', 'auth'))
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateState)
        .expect(auth.validateError('access_denied'))
        .expect(auth.validateErrorDescription('End-User aborted interaction'));
    });
  });

  describe('submit login', () => {
    const fixture6 = Object.create(fixture);

    beforeEach(() => fixture6.logout(), { timeout: 3000 });
    beforeEach(() => {
      const auth = new fixture6.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });
      fixture6.auth = auth;

      return fixture6.agent.get('/auth')
        .query(auth)
        .then((response) => {
          fixture6.url = response.headers.location;
        });
    }, { timeout: 3000 });

    it('accepts the login and resumes auth', { timeout: 3000 }, async () => {
      let location;
      await fixture6.agent.post(`${fixture6.url}`)
        .send({
          prompt: 'login',
          login: 'foobar',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(fixture6.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await fixture6.agent.get(new URL(location).pathname)
        .expect(303);
    });

    it('checks that the account is a non empty string', { timeout: 3000 }, async () => {
      let location;
      const spy = sinon.spy();
      fixture6.provider.once('server_error', spy);

      await fixture6.agent.post(`${fixture6.url}`)
        .send({
          prompt: 'login',
          login: '',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(fixture6.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await fixture6.agent.get(new URL(location).pathname)
        .expect(500);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const error = spy.firstCall.args[1];
      ((actual) => { assert.ok(actual instanceof TypeError); })(error);
      ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'accountId must be a non-empty string, got: string'); })(error);
    });

    handlesInteractionSessionErrors(fixture6);
  });

  describe('submit consent', () => {
    const fixture7 = Object.create(fixture);

    beforeEach(() => fixture7.logout(), { timeout: 3000 });
    beforeEach(() => fixture7.login(), { timeout: 3000 });
    beforeEach(() => {
      const auth = new fixture7.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'consent',
      });

      return fixture7.agent.get('/auth')
        .query(auth)
        .then((response) => {
          fixture7.url = response.headers.location;
        });
    }, { timeout: 3000 });

    it('accepts the consent and resumes auth', { timeout: 3000 }, async () => {
      let location;
      await fixture7.agent.post(`${fixture7.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(fixture7.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await fixture7.agent.get(new URL(location).pathname)
        .expect(303);
    });

    it('checks the session interaction came from still exists', { timeout: 3000 }, async () => {
      let location;
      await fixture7.agent.post(`${fixture7.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(fixture7.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      const session = fixture7.getSession({ instantiate: true });
      await session.destroy();

      await fixture7.agent.get(new URL(location).pathname)
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/interaction session and authentication session mismatch/);
    });

    it('checks the session interaction came from is still the one', { timeout: 3000 }, async () => {
      let location;
      await fixture7.agent.post(`${fixture7.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(fixture7.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await fixture7.login();

      await fixture7.agent.get(new URL(location).pathname)
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/interaction session and authentication session mismatch/);
    });

    it('checks the session interaction came from is still the one', { timeout: 3000 }, async () => {
      let location;
      await fixture7.agent.post(`${fixture7.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(fixture7.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await fixture7.login();

      await fixture7.agent.get(new URL(location).pathname)
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/interaction session and authentication session mismatch/);
    });

    handlesInteractionSessionErrors(fixture7);
  });
});

describe('resume after consent', () => {
  const fixture8 = {};

  before(bootstrap(import.meta.url, fixture8), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  function setup(grant, result, sessionData) {
    const cookies = [];

    let session;
    if (result?.login) {
      session = new this.provider.Session({ jti: 'sess', ...sessionData });
    } else {
      session = this.getLastSession();
    }
    const interaction = new this.provider.Interaction('resume', {
      uid: 'resume',
      params: grant,
      session,
    });

    assert.ok(grant);

    const cookie = `_interaction_resume=resume; path=${this.suitePath('/auth/resume')}; expires=${expire.toGMTString()}; httponly`;
    cookies.push(cookie);

    const sessionCookie = `_session=${session.jti || 'sess'}; path=/; expires=${expire.toGMTString()}; httponly`;
    cookies.push(sessionCookie);

    if (result) {
      if (result.login && !result.login.ts) {
        Object.assign(result.login, { ts: epochTime() });
      }
      Object.assign(interaction, { result });
    }

    this.agent._saveCookies.bind(this.agent)({
      request: { url: this.provider.issuer },
      headers: { 'set-cookie': cookies },
    });

    return Promise.all([
      interaction.save(30), // TODO: bother running the ttl helper?
      session.save(30), // TODO: bother running the ttl helper?
    ]);
  }

  describe('general', () => {
    const fixture9 = Object.create(fixture8);

    before(() => fixture9.login(), { timeout: 3000 });
    after(() => fixture9.logout(), { timeout: 3000 });

    it('needs the resume cookie to be present, else renders an err', { timeout: 3000 }, () => fixture9.agent.get('/auth/resume')
        .expect(400)
        .expect(/authorization request has expired/));

    it('needs to find the session to resume', { timeout: 3000 }, async () => {
      const auth = new fixture9.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(fixture9, auth);

      sinon.stub(fixture9.provider.Interaction, 'find').resolves();

      return fixture9.agent.get('/auth/resume')
        .expect(400)
        .expect(/interaction session not found/);
    });
  });

  describe('login results', () => {
    const fixture10 = Object.create(fixture8);

    it('should process newly established permanent sessions (default)', { timeout: 3000 }, async () => {
      sinon.stub(fixture10.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new fixture10.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(fixture10, auth, {
        login: {
          accountId: nanoid(),
        },
      });

      return fixture10.agent.get('/auth/resume')
        .expect(303)
        .expect('set-cookie', /expires/) // expect a permanent cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(() => {
          ((actual) => { assert.ok(actual); assert.ok(!('transient' in Object(actual))); })(fixture10.getSession());
        });
    });

    it('should process newly established permanent sessions (explicit)', { timeout: 3000 }, async () => {
      sinon.stub(fixture10.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new fixture10.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(fixture10, auth, {
        login: {
          accountId: nanoid(),
          remember: true,
        },
      });

      return fixture10.agent.get('/auth/resume')
        .expect(303)
        .expect('set-cookie', /expires/) // expect a permanent cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(() => {
          ((actual) => { assert.ok(actual); assert.ok(!('transient' in Object(actual))); })(fixture10.getSession());
        });
    });

    it('should process newly established temporary sessions', { timeout: 3000 }, async () => {
      sinon.stub(fixture10.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new fixture10.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(fixture10, auth, {
        login: {
          accountId: nanoid(),
          remember: false,
        },
      });

      return fixture10.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect('set-cookie', /_session=((?!expires).)+/) // expect a transient session cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(() => {
          ((actual) => { assert.ok(actual); assert.ok('transient' in Object(actual)); })(fixture10.getSession());
        });
    });

    it('should trigger logout when the session subject changes', { timeout: 3000 }, async () => {
      sinon.stub(fixture10.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new fixture10.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(fixture10, auth, {
        login: {
          accountId: nanoid(),
        },
      }, {
        accountId: nanoid(),
      });

      let state;

      await fixture10.agent.get('/auth/resume')
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/document.addEventListener\('DOMContentLoaded', function \(\) { document.forms\[0\].submit\(\) }\);/)
        .expect(/<input type="hidden" name="logout" value="yes"\/>/)
        .expect(({ text }) => {
          ({ state } = fixture10.getSession());
          ((actual) => { assert.ok('clientId' in Object(actual)); assert.equal(actual.clientId, 'client'); })(state);
          ((actual) => { assert.ok('postLogoutRedirectUri' in Object(actual)); assert.match(actual.postLogoutRedirectUri, /\/auth\/resume$/); })(state);
          assert.match(text, new RegExp(`input type="hidden" name="xsrf" value="${state.secret}"`));
        })
        .expect(/<form method="post" action=".+\/session\/end\/confirm">/);

      assert.ok(await fixture10.provider.Interaction.find('resume'));

      await fixture10.agent.post('/session/end/confirm')
        .send({
          xsrf: state.secret,
          logout: 'yes',
        })
        .type('form')
        .expect(303)
        .expect('location', /\/auth\/resume$/);

      await fixture10.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateState);
    });
  });

  describe('custom interaction errors', () => {
    const fixture11 = Object.create(fixture8);

    describe('when prompt=none', () => {
      const fixture12 = Object.create(fixture11);

      before(() => fixture12.login(), { timeout: 3000 });
      after(() => fixture12.logout(), { timeout: 3000 });
      it('custom interactions can fail too (prompt none)', { timeout: 3000 }, async () => {
        const auth = new fixture12.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          triggerCustomFail: 'foo',
          prompt: 'none',
        });

        return fixture12.agent.get('/auth')
          .query(auth)
          .expect(303)
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('error_foo'))
          .expect(auth.validateErrorDescription('error_description_foo'));
      });
    });

    it('custom interactions can fail too', { timeout: 3000 }, async () => {
      const auth = new fixture11.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        triggerCustomFail: 'foo',
      });

      await setup.call(fixture11, auth, {
        login: {
          accountId: nanoid(),
          remember: true,
        },
        consent: {},
      });

      return fixture11.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('login', 'reason_foo'));
    });
  });

  describe('interaction errors', () => {
    const fixture13 = Object.create(fixture8);

    it('should abort an interaction when given an error result object (no description)', { timeout: 3000 }, async () => {
      const auth = new fixture13.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(fixture13, auth, {
        error: 'access_denied',
      });

      return fixture13.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['error', 'state']))
        .expect(auth.validateError('access_denied'));
    });

    it('should abort an interaction when given an error result object (with state)', { timeout: 3000 }, async () => {
      const auth = new fixture13.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        state: 'bf458-00aa3',
      });

      await setup.call(fixture13, auth, {
        error: 'access_denied',
      });

      return fixture13.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['error', 'state']))
        .expect(auth.validateError('access_denied'));
    });

    it('should abort an interaction when given an error result object (with description)', { timeout: 3000 }, async () => {
      const auth = new fixture13.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(fixture13, auth, {
        error: 'access_denied',
        error_description: 'scope out of reach',
      });

      return fixture13.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validateError('access_denied'))
        .expect(auth.validateErrorDescription('scope out of reach'));
    });

    it('should abort an interaction when given an error result object (custom error)', { timeout: 3000 }, async () => {
      const auth = new fixture13.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(fixture13, auth, {
        error: 'custom_foo',
        error_description: 'custom_foobar',
      });

      return fixture13.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validateError('custom_foo'))
        .expect(auth.validateErrorDescription('custom_foobar'));
    });
  });

  describe('custom requestable prompts', () => {
    const fixture14 = Object.create(fixture8);

    before(() => fixture14.login(), { timeout: 3000 });
    after(() => fixture14.logout(), { timeout: 3000 });

    it('should fail if they are not resolved', { timeout: 3000 }, async () => {
      const auth = new fixture14.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'custom',
      });

      await setup.call(fixture14, auth, {});

      return fixture14.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('custom', 'custom_prompt'));
    });
  });

  describe('custom unrequestable prompts', () => {
    const fixture15 = Object.create(fixture8);

    it('should prompt interaction', { timeout: 3000 }, async () => {
      const auth = new fixture15.AuthorizationRequest({
        response_type: 'code',
        triggerUnrequestable: 'foo',
        response_mode: 'query',
        scope: 'openid',
      });

      return fixture15.agent.get('/auth')
        .query(auth)
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('unrequestable', 'un_foo'));
    });

    it('should fail if they are not satisfied', { timeout: 3000 }, async () => {
      const auth = new fixture15.AuthorizationRequest({
        response_type: 'code',
        triggerUnrequestable: 'foo',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(fixture15, auth, {
        login: {
          accountId: nanoid(),
          remember: true,
        },
        consent: {},
      });

      return fixture15.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('unrequestable', 'un_foo'));
    });
  });
});
