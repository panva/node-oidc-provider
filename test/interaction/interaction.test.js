/* eslint-disable no-underscore-dangle */

import { strict as assert } from 'node:assert';

import { expect } from 'chai';
import KeyGrip from 'keygrip'; // eslint-disable-line import/no-extraneous-dependencies
import { createSandbox } from 'sinon';

import nanoid from '../../lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

const sinon = createSandbox();

const expire = new Date();
expire.setDate(expire.getDate() + 1);
const expired = new Date(0);

function handlesInteractionSessionErrors() {
  it('"handles" not found interaction session id cookie', async function () {
    const cookies = [
      `_interaction=; path=${this.url}; expires=${expired.toGMTString()}; httponly`,
      `_interaction.sig=; path=${this.url}; expires=${expired.toGMTString()}; httponly`,
    ];
    this.agent._saveCookies.bind(this.agent)({
      request: { url: this.provider.issuer },
      headers: { 'set-cookie': cookies },
    });

    sinon.spy(this.provider, 'interactionDetails');

    await this.agent.get(this.url).expect(400);
    return assert.rejects(this.provider.interactionDetails.getCall(0).returnValue, (err) => {
      expect(err.name).to.eql('SessionNotFound');
      expect(err.error_description).to.eql('interaction session id cookie not found');
      return true;
    });
  });

  it('"handles" not found interaction session', async function () {
    sinon.stub(this.provider.Interaction, 'find').resolves();

    sinon.spy(this.provider, 'interactionDetails');

    await this.agent.get(this.url).expect(400);
    return assert.rejects(this.provider.interactionDetails.getCall(0).returnValue, (err) => {
      expect(err.name).to.eql('SessionNotFound');
      expect(err.error_description).to.eql('interaction session not found');
      return true;
    });
  });
}
describe('devInteractions', () => {
  before(bootstrap(import.meta.url));
  afterEach(sinon.restore);

  context('render login', () => {
    beforeEach(function () { return this.logout(); });
    beforeEach(function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      return this.agent.get('/auth')
        .query(auth)
        .then((response) => {
          this.url = response.headers.location;
        });
    });

    it('with a form', function () {
      return this.agent.get(this.url)
        .expect(200)
        .expect(new RegExp(`action="${this.provider.issuer}${this.url}"`))
        .expect(/name="prompt" value="login"/)
        .expect(/Sign-in/);
    });

    handlesInteractionSessionErrors();
  });

  context('render interaction', () => {
    beforeEach(function () { return this.logout(); });
    beforeEach(function () { return this.login(); });
    beforeEach(function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'consent',
      });

      return this.agent.get('/auth')
        .query(auth)
        .then((response) => {
          this.url = response.headers.location;
        });
    });

    it('with a form', function () {
      return this.agent.get(this.url)
        .expect(200)
        .expect(new RegExp(`action="${this.provider.issuer}${this.url}"`))
        .expect(/name="prompt" value="consent"/)
        .expect(/Authorize/);
    });

    it('checks that the authentication session is still there', async function () {
      const session = this.getSession({ instantiate: true });
      await session.destroy();

      await this.agent.get(this.url)
        .accept('text/html')
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/session not found/);
    });

    it("checks that the authentication session's principal didn't change", async function () {
      const session = this.getSession({ instantiate: true });
      session.accountId = 'foobar';
      await session.persist();

      await this.agent.get(this.url)
        .accept('text/html')
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/session principal changed/);
    });
  });

  context('when unimplemented prompt is requested', () => {
    beforeEach(function () { return this.logout(); });

    it('throws a 501', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      const url = await this.agent.get('/auth')
        .query(auth)
        .then((response) => response.headers.location);

      const split = url.split('/');
      const uid = split[split.length - 1];
      const interaction = this.TestAdapter.for('Interaction').syncFind(uid);
      interaction.prompt.name = 'notimplemented';

      return this.agent.get(url).expect(501);
    });
  });

  context('navigate to abort', () => {
    before(function () { return this.logout(); });

    it('should abort an interaction with an error', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await this.agent.get('/auth')
        .query(auth)
        .then((response) => {
          this.url = response.headers.location;
        });

      await this.agent.get(`${this.url}/abort`)
        .expect(303)
        .expect(({ headers: { location } }) => {
          this.location = location;
        });

      return this.agent.get(this.url.replace('interaction', 'auth'))
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateState)
        .expect(auth.validateError('access_denied'))
        .expect(auth.validateErrorDescription('End-User aborted interaction'));
    });
  });

  context('submit login', () => {
    beforeEach(function () { return this.logout(); });
    beforeEach(function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });
      this.auth = auth;

      return this.agent.get('/auth')
        .query(auth)
        .then((response) => {
          this.url = response.headers.location;
        });
    });

    it('accepts the login and resumes auth', async function () {
      let location;
      await this.agent.post(`${this.url}`)
        .send({
          prompt: 'login',
          login: 'foobar',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await this.agent.get(new URL(location).pathname)
        .expect(303);
    });

    it('checks that the account is a non empty string', async function () {
      let location;
      const spy = sinon.spy();
      this.provider.once('server_error', spy);

      await this.agent.post(`${this.url}`)
        .send({
          prompt: 'login',
          login: '',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await this.agent.get(new URL(location).pathname)
        .expect(500);

      expect(spy).to.have.property('calledOnce', true);
      const error = spy.firstCall.args[1];
      expect(error).to.be.an.instanceof(TypeError);
      expect(error).to.have.property('message', 'accountId must be a non-empty string, got: string');
    });

    handlesInteractionSessionErrors();
  });

  context('submit consent', () => {
    beforeEach(function () { return this.logout(); });
    beforeEach(function () { return this.login(); });
    beforeEach(function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'consent',
      });

      return this.agent.get('/auth')
        .query(auth)
        .then((response) => {
          this.url = response.headers.location;
        });
    });

    it('accepts the consent and resumes auth', async function () {
      let location;
      await this.agent.post(`${this.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await this.agent.get(new URL(location).pathname)
        .expect(303);
    });

    it('checks the session interaction came from still exists', async function () {
      let location;
      await this.agent.post(`${this.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      const session = this.getSession({ instantiate: true });
      await session.destroy();

      await this.agent.get(new URL(location).pathname)
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/interaction session and authentication session mismatch/);
    });

    it('checks the session interaction came from is still the one', async function () {
      let location;
      await this.agent.post(`${this.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await this.login();

      await this.agent.get(new URL(location).pathname)
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/interaction session and authentication session mismatch/);
    });

    it('checks the session interaction came from is still the one', async function () {
      let location;
      await this.agent.post(`${this.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(303)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')))
        .expect(({ headers }) => {
          ({ location } = headers);
        });

      await this.login();

      await this.agent.get(new URL(location).pathname)
        .expect(400)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/interaction session and authentication session mismatch/);
    });

    handlesInteractionSessionErrors();
  });
});

describe('resume after consent', () => {
  before(bootstrap(import.meta.url));
  afterEach(sinon.restore);

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
    const keys = new KeyGrip(i(this.provider).configuration('cookies.keys'));

    expect(grant).to.be.ok;

    const cookie = `_interaction_resume=resume; path=${this.suitePath('/auth/resume')}; expires=${expire.toGMTString()}; httponly`;
    cookies.push(cookie);
    let [pre, ...post] = cookie.split(';');
    cookies.push([`_interaction_resume.sig=${keys.sign(pre)}`, ...post].join(';'));

    const sessionCookie = `_session=${session.jti || 'sess'}; path=/; expires=${expire.toGMTString()}; httponly`;
    cookies.push(sessionCookie);
    [pre, ...post] = sessionCookie.split(';');
    cookies.push([`_session.sig=${keys.sign(pre)}`, ...post].join(';'));

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

  context('general', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('needs the resume cookie to be present, else renders an err', function () {
      return this.agent.get('/auth/resume')
        .expect(400)
        .expect(/authorization request has expired/);
    });

    it('needs to find the session to resume', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(this, auth);

      sinon.stub(this.provider.Interaction, 'find').resolves();

      return this.agent.get('/auth/resume')
        .expect(400)
        .expect(/interaction session not found/);
    });
  });

  context('login results', () => {
    it('should process newly established permanent sessions (default)', async function () {
      sinon.stub(this.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          accountId: nanoid(),
        },
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect('set-cookie', /expires/) // expect a permanent cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(() => {
          expect(this.getSession()).to.be.ok.and.not.have.property('transient');
        });
    });

    it('should process newly established permanent sessions (explicit)', async function () {
      sinon.stub(this.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          accountId: nanoid(),
          remember: true,
        },
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect('set-cookie', /expires/) // expect a permanent cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(() => {
          expect(this.getSession()).to.be.ok.and.not.have.property('transient');
        });
    });

    it('should process newly established temporary sessions', async function () {
      sinon.stub(this.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          accountId: nanoid(),
          remember: false,
        },
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect('set-cookie', /_session=((?!expires).)+,/) // expect a transient session cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(() => {
          expect(this.getSession()).to.be.ok.and.have.property('transient');
        });
    });

    it('should trigger logout when the session subject changes', async function () {
      sinon.stub(this.provider.Grant.prototype, 'getOIDCScope').returns('openid');
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          accountId: nanoid(),
        },
      }, {
        accountId: nanoid(),
      });

      let state;

      await this.agent.get('/auth/resume')
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/document.addEventListener\('DOMContentLoaded', function \(\) { document.forms\[0\].submit\(\) }\);/)
        .expect(/<input type="hidden" name="logout" value="yes"\/>/)
        .expect(({ text }) => {
          ({ state } = this.getSession());
          expect(state).to.have.property('clientId', 'client');
          expect(state).to.have.property('postLogoutRedirectUri').that.matches(/\/auth\/resume$/);
          expect(text).to.match(new RegExp(`input type="hidden" name="xsrf" value="${state.secret}"`));
        })
        .expect(/<form method="post" action=".+\/session\/end\/confirm">/);

      expect(await this.provider.Interaction.find('resume')).to.be.ok;

      await this.agent.post('/session/end/confirm')
        .send({
          xsrf: state.secret,
          logout: 'yes',
        })
        .type('form')
        .expect(303)
        .expect('location', /\/auth\/resume$/);

      await this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateState);
    });
  });

  describe('custom interaction errors', () => {
    describe('when prompt=none', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });
      it('custom interactions can fail too (prompt none)', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          triggerCustomFail: 'foo',
          prompt: 'none',
        });

        return this.agent.get('/auth')
          .query(auth)
          .expect(303)
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('error_foo'))
          .expect(auth.validateErrorDescription('error_description_foo'));
      });
    });

    it('custom interactions can fail too', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        triggerCustomFail: 'foo',
      });

      await setup.call(this, auth, {
        login: {
          accountId: nanoid(),
          remember: true,
        },
        consent: {},
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('login', 'reason_foo'));
    });
  });

  context('interaction errors', () => {
    it('should abort an interaction when given an error result object (no description)', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        error: 'access_denied',
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['error', 'state']))
        .expect(auth.validateError('access_denied'));
    });

    it('should abort an interaction when given an error result object (with state)', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        state: 'bf458-00aa3',
      });

      await setup.call(this, auth, {
        error: 'access_denied',
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['error', 'state']))
        .expect(auth.validateError('access_denied'));
    });

    it('should abort an interaction when given an error result object (with description)', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        error: 'access_denied',
        error_description: 'scope out of reach',
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validateError('access_denied'))
        .expect(auth.validateErrorDescription('scope out of reach'));
    });

    it('should abort an interaction when given an error result object (custom error)', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        error: 'custom_foo',
        error_description: 'custom_foobar',
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateState)
        .expect(auth.validateError('custom_foo'))
        .expect(auth.validateErrorDescription('custom_foobar'));
    });
  });

  context('custom requestable prompts', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('should fail if they are not resolved', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'custom',
      });

      await setup.call(this, auth, {});

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('custom', 'custom_prompt'));
    });
  });

  context('custom unrequestable prompts', () => {
    it('should prompt interaction', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        triggerUnrequestable: 'foo',
        response_mode: 'query',
        scope: 'openid',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('unrequestable', 'un_foo'));
    });

    it('should fail if they are not satisfied', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        triggerUnrequestable: 'foo',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          accountId: nanoid(),
          remember: true,
        },
        consent: {},
      });

      return this.agent.get('/auth/resume')
        .expect(303)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('unrequestable', 'un_foo'));
    });
  });
});
