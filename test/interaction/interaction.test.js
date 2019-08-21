/* eslint-disable no-underscore-dangle */

const { expect } = require('chai');
const KeyGrip = require('keygrip'); // eslint-disable-line import/no-extraneous-dependencies
const sinon = require('sinon');

const nanoid = require('../../lib/helpers/nanoid');
const bootstrap = require('../test_helper');
const epochTime = require('../../lib/helpers/epoch_time');

const config = require('./interaction.config');

const expire = new Date();
expire.setDate(expire.getDate() + 1);
const expired = new Date(0);
const fail = () => { throw new Error('expected promise to be rejected'); };

function handlesInteractionSessionErrors() {
  it('"handles" not found interaction session id cookie', async function () {
    const cookies = [
      `_interaction=; path=${this.url}; expires=${expired.toGMTString()}; httponly`,
      `_interaction.sig=; path=${this.url}; expires=${expired.toGMTString()}; httponly`,
    ];
    this.agent._saveCookies.bind(this.agent)({ headers: { 'set-cookie': cookies } });

    sinon.spy(this.provider, 'interactionDetails');

    await this.agent.get(this.url).expect(400);
    await this.provider.interactionDetails.getCall(0).returnValue.then(fail, (err) => {
      expect(err.name).to.eql('SessionNotFound');
      expect(err.error_description).to.eql('interaction session id cookie not found');
    });
  });

  it('"handles" not found interaction session', async function () {
    sinon.stub(this.provider.Interaction, 'find').resolves();

    sinon.spy(this.provider, 'interactionDetails');

    await this.agent.get(this.url).expect(400);
    await this.provider.interactionDetails.getCall(0).returnValue.then(fail, (err) => {
      expect(err.name).to.eql('SessionNotFound');
      expect(err.error_description).to.eql('interaction session not found');
    });
  });
}

describe('devInteractions', () => {
  before(bootstrap(__dirname));
  afterEach(function () {
    if (this.provider.Interaction.find.restore) {
      this.provider.Interaction.find.restore();
    }

    if (this.provider.interactionDetails.restore) {
      this.provider.interactionDetails.restore();
    }

    if (this.provider.interactionFinished.restore) {
      this.provider.interactionFinished.restore();
    }
  });

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
        .expect(new RegExp(`action="${this.url}"`))
        .expect(new RegExp('name="prompt" value="login"'))
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
        .expect(new RegExp(`action="${this.url}"`))
        .expect(new RegExp('name="prompt" value="consent"'))
        .expect(/Authorize/);
    });

    handlesInteractionSessionErrors();
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

      const interaction = this.TestAdapter.for('Interaction').syncFind(url.split('/')[2]);
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
        .expect(302)
        .expect(({ headers: { location } }) => {
          this.location = location;
        });

      return this.agent.get(this.url.replace('interaction', 'auth'))
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
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

      return this.agent.get('/auth')
        .query(auth)
        .then((response) => {
          this.url = response.headers.location;
        });
    });

    it('accepts the login and resumes auth', function () {
      return this.agent.post(`${this.url}`)
        .send({
          prompt: 'login',
          login: 'foobar',
        })
        .type('form')
        .expect(302)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')));
    });

    handlesInteractionSessionErrors();
  });

  context('submit interaction', () => {
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

    it('accepts the interaction and resumes auth', function () {
      return this.agent.post(`${this.url}`)
        .send({
          prompt: 'consent',
        })
        .type('form')
        .expect(302)
        .expect('location', new RegExp(this.url.replace('interaction', 'auth')));
    });

    handlesInteractionSessionErrors();
  });
});

describe('resume after interaction', () => {
  before(bootstrap(__dirname));

  afterEach(function () {
    if (this.provider.Interaction.find.restore) {
      this.provider.Interaction.find.restore();
    }
  });

  function setup(grant, result, sessionData) {
    const cookies = [];

    const interaction = new this.provider.Interaction('resume', {});
    const session = new this.provider.Session({ jti: 'sess', ...sessionData });
    const keys = new KeyGrip(i(this.provider).configuration('cookies.keys'));

    expect(grant).to.be.ok;

    const cookie = `_interaction_resume=resume; path=/auth/resume; expires=${expire.toGMTString()}; httponly`;
    cookies.push(cookie);
    let [pre, ...post] = cookie.split(';');
    cookies.push([`_interaction_resume.sig=${keys.sign(pre)}`, ...post].join(';'));
    Object.assign(interaction, { params: grant });

    const sessionCookie = `_session=sess; path=/; expires=${expire.toGMTString()}; httponly`;
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
      headers: {
        'set-cookie': cookies,
      },
    });

    return Promise.all([
      interaction.save(),
      session.save(),
    ]);
  }

  context('general', () => {
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
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          account: nanoid(),
        },
        consent: {},
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect('set-cookie', /expires/) // expect a permanent cookie
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state', 'session_state']))
        .expect(() => {
          expect(this.getSession()).to.be.ok.and.not.have.property('transient');
        });
    });

    // WebKit treats unrecognized (yet) "None" value as "Strict" instead
    // https://bugs.webkit.org/show_bug.cgi?id=198181
    // TODO: remove when no longer needed
    Object.entries({
      // Blink
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36': true,
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36': true,
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36': true,
      'Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36': true,
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36': true,
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763': true,
      'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.9200': true,

      // Gecko
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0': true,
      'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.10) Gecko/20050716 Firefox/1.0.6': true,

      // Trident
      'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko': true,
      'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)': true,
      'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)': true,

      // WebKit
      'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e Safari/602.1': false,
      'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/603.1.23 (KHTML, like Gecko) Version/10.0 Mobile/14E5239e Safari/602.1': false,
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12': false,
      'Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148': false,
      'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148': false,
      'Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1': false,
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko)': false,
      'Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19': false,
      'Mozilla/5.0 (Linux; Android 4.2.1; en-us; Nexus 5 Build/JOP40D) AppleWebKit/535.19 (KHTML, like Gecko; googleweblight) Chrome/38.0.1025.166 Mobile Safari/535.19': false,
    }).forEach(([ua, samesite], i, { length }) => {
      it(`should not set samesite=none to webkit based browsers for now (${i + 1}/${length})`, async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid',
        });

        await setup.call(this, auth, {
          login: {
            account: nanoid(),
          },
          consent: {},
        });

        return this.agent.get('/auth/resume')
          .set('user-agent', ua)
          .expect(302)
          .expect('set-cookie', samesite ? /samesite=none/ : /^((?!samesite=none).)+$/)
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validatePresence(['code', 'state', 'session_state']))
          .expect(() => {
            expect(this.getSession()).to.be.ok.and.not.have.property('transient');
          });
      });
    });

    it('should process newly established permanent sessions (explicit)', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          account: nanoid(),
          remember: true,
        },
        consent: {},
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect('set-cookie', /expires/) // expect a permanent cookie
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state', 'session_state']))
        .expect(() => {
          expect(this.getSession()).to.be.ok.and.not.have.property('transient');
        });
    });

    it('should process newly established temporary sessions', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          account: nanoid(),
          remember: false,
        },
        consent: {},
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect('set-cookie', /_session=((?!expires).)+,/) // expect a transient session cookie
        .expect('set-cookie', /_state\.client=((?!expires).)+,/) // expect a transient session cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state', 'session_state']))
        .expect(() => {
          expect(this.getSession()).to.be.ok.and.have.property('transient');
        });
    });

    it('should trigger logout when the session subject changes', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          account: nanoid(),
        },
        consent: {},
      }, {
        account: nanoid(),
      });

      await this.agent.get('/auth/resume')
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/<body onload="javascript:document\.forms\[0]\.submit\(\)"/)
        .expect(/<input type="hidden" name="logout" value="yes"\/>/)
        .expect(({ text }) => {
          const { state } = this.getSession();
          expect(state).to.have.property('clientId', 'client');
          expect(state).to.have.property('postLogoutRedirectUri').that.matches(/\/auth\/resume$/);
          expect(text).to.match(new RegExp(`input type="hidden" name="xsrf" value="${state.secret}"`));
        })
        .expect(/<form method="post" action=".+\/session\/end\/confirm">/);

      expect(await this.provider.Interaction.find('resume')).to.be.ok;
    });
  });

  context('consent results', () => {
    it('when scope includes offline_access', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        prompt: 'consent',
        scope: 'openid offline_access',
      });

      await setup.call(this, auth, {
        login: {
          account: nanoid(),
          remember: true,
        },
        consent: {},
      });

      let authorizationCode;

      this.provider.once('authorization_code.saved', (code) => {
        authorizationCode = code;
      });

      return this.agent.get('/auth/resume')
        .expect(() => {
          expect(authorizationCode).to.be.ok;
          expect(authorizationCode).to.have.property('scope', 'openid offline_access');
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
            .expect(302)
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
            account: nanoid(),
            remember: true,
          },
          consent: {},
        });

        return this.agent.get('/auth/resume')
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'reason_foo'));
      });
    });

    describe('rejectedScopes', () => {
      it('allows for scopes to be rejected', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid profile',
        });

        await setup.call(this, auth, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {
            rejectedScopes: ['profile'],
          },
        });

        let authorizationCode;

        this.provider.once('authorization_code.saved', (code) => {
          authorizationCode = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid');
          });
      });

      it('prompted & rejected scopes can be accumulated over time', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid profile email',
        });

        await setup.call(this, auth, {
          consent: {
            rejectedScopes: ['email'],
          },
        }, {
          account: nanoid(),
          authorizations: {
            client: {
              sid: 'foo',
              grantId: 'foo',
              rejectedScopes: ['profile'],
              promptedScopes: ['openid', 'profile'],
            },
          },
        });

        let authorizationCode;
        let session;
        this.provider.once('authorization_code.saved', (code) => {
          authorizationCode = code;
        });
        this.provider.once('session.saved', (code) => {
          session = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            expect(session).to.be.ok;
            expect(session).to.have.nested.deep.property('authorizations.client.promptedScopes', ['openid', 'profile', 'email']);
            expect(session).to.have.nested.deep.property('authorizations.client.rejectedScopes', ['profile', 'email']);
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid');
          });
      });

      it('existing rejected scopes can be replaced', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid profile email',
        });

        await setup.call(this, auth, {
          consent: {
            rejectedScopes: [],
            replace: true,
          },
        }, {
          account: nanoid(),
          authorizations: {
            client: {
              sid: 'foo',
              grantId: 'foo',
              rejectedScopes: ['profile'],
              promptedScopes: ['openid', 'profile'],
            },
          },
        });

        let authorizationCode;
        let session;
        this.provider.once('authorization_code.saved', (code) => {
          authorizationCode = code;
        });
        this.provider.once('session.saved', (code) => {
          session = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            expect(session).to.be.ok;
            expect(session).to.have.nested.deep.property('authorizations.client.promptedScopes', ['openid', 'profile', 'email']);
            expect(session).to.have.nested.deep.property('authorizations.client.rejectedScopes', []);
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid profile email');
          });
      });

      it('cannot reject openid scope', async function () {
        const spy = sinon.spy();
        this.provider.once('server_error', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid',
          prompt: 'consent',
        });

        await setup.call(this, auth, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {
            rejectedScopes: ['openid'],
          },
        });

        await this.agent.get('/auth/resume')
          .expect(302)
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('server_error'));

        expect(spy).to.have.property('calledOnce', true);
        const error = spy.firstCall.args[1];
        expect(error).to.be.an.instanceof(Error);
        expect(error).to.have.property('message', 'openid cannot be rejected');
      });

      it('must be passed as Set or Array', async function () {
        const spy = sinon.spy();
        this.provider.once('server_error', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          prompt: 'consent',
        });

        await setup.call(this, auth, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {
            rejectedScopes: 'openid',
          },
        });

        await this.agent.get('/auth/resume')
          .expect(302)
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('server_error'));

        expect(spy).to.have.property('calledOnce', true);
        const error = spy.firstCall.args[1];
        expect(error).to.be.an.instanceof(Error);
        expect(error).to.have.property('message', 'expected Array or Set');
      });
    });

    describe('rejectedClaims', () => {
      it('allows for claims to be rejected', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid profile',
        });

        await setup.call(this, auth, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {
            rejectedClaims: ['nickname'],
          },
        });

        let authorizationCode;

        this.provider.once('authorization_code.saved', (code) => {
          authorizationCode = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid profile');
            expect(authorizationCode).to.have.deep.property('claims', { rejected: ['nickname'] });
          });
      });

      it('prompted & rejected claims can be accumulated over time', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid profile email',
        });

        await setup.call(this, auth, {
          consent: {
            rejectedClaims: ['email'],
          },
        }, {
          account: nanoid(),
          authorizations: {
            client: {
              sid: 'foo',
              grantId: 'foo',
              rejectedClaims: ['nickname'],
              promptedClaims: ['nickname'],
            },
          },
        });

        let authorizationCode;
        let session;

        this.provider.once('authorization_code.saved', (code) => {
          authorizationCode = code;
        });
        this.provider.once('session.saved', (code) => {
          session = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            expect(session).to.be.ok;
            expect(session).to.have.nested.deep.property('authorizations.client.rejectedClaims', ['nickname', 'email']);
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid profile email');
            expect(authorizationCode).to.have.deep.property('claims', { rejected: ['nickname', 'email'] });
          });
      });

      it('existing rejected claims can be replaced', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'query',
          scope: 'openid profile email',
        });

        await setup.call(this, auth, {
          consent: {
            rejectedClaims: [],
            replace: true,
          },
        }, {
          account: nanoid(),
          authorizations: {
            client: {
              sid: 'foo',
              grantId: 'foo',
              rejectedClaims: ['nickname'],
            },
          },
        });

        let authorizationCode;
        let session;

        this.provider.once('authorization_code.saved', (code) => {
          authorizationCode = code;
        });
        this.provider.once('session.saved', (code) => {
          session = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            expect(session).to.be.ok;
            expect(session).to.have.nested.deep.property('authorizations.client.rejectedClaims', []);
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid profile email');
            expect(authorizationCode).to.have.deep.property('claims', { rejected: [] });
          });
      });

      ['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].forEach((claim) => {
        it(`cannot reject ${claim} claim`, async function () {
          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid',
            prompt: 'consent',
          });

          await setup.call(this, auth, {
            login: {
              account: nanoid(),
              remember: true,
            },
            consent: {
              rejectedClaims: [claim],
            },
          });

          await this.agent.get('/auth/resume')
            .expect(302)
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('server_error'));

          expect(spy).to.have.property('calledOnce', true);
          const error = spy.firstCall.args[1];
          expect(error).to.be.an.instanceof(Error);
          expect(error).to.have.property('message', `${claim} cannot be rejected`);
        });
      });

      it('must be passed as Set or Array', async function () {
        const spy = sinon.spy();
        this.provider.once('server_error', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          prompt: 'consent',
        });

        await setup.call(this, auth, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {
            rejectedClaims: 'email',
          },
        });

        await this.agent.get('/auth/resume')
          .expect(302)
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('server_error'));

        expect(spy).to.have.property('calledOnce', true);
        const error = spy.firstCall.args[1];
        expect(error).to.be.an.instanceof(Error);
        expect(error).to.have.property('message', 'expected Array or Set');
      });
    });
  });

  context('meta results', () => {
    it('should process and store meta-informations provided alongside login', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'fragment',
        scope: 'openid',
      });

      await setup.call(this, auth, {
        login: {
          account: nanoid(),
          remember: true,
        },
        meta: {
          scope: 'openid',
        },
      });

      return this.agent.get('/auth/resume')
        .expect(() => {
          const session = this.getSession({ instantiate: true });
          const meta = session.metaFor(config.client.client_id);
          expect(meta).to.be.ok;
          expect(meta).to.have.property('scope');
        });
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
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['error', 'state', 'session_state']))
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
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validatePresence(['error', 'state', 'session_state']))
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
        .expect(302)
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
        .expect(302)
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

      await setup.call(this, auth, {
        login: {
          account: nanoid(),
          remember: true,
        },
        consent: {},
      });

      return this.agent.get('/auth/resume')
        .expect(302)
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
        .expect(302)
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
          account: nanoid(),
          remember: true,
        },
        consent: {},
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteraction('unrequestable', 'un_foo'));
    });
  });
});
