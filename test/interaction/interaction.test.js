/* eslint-disable no-underscore-dangle */

const { expect } = require('chai');
const uuid = require('uuid/v4');
const KeyGrip = require('keygrip'); // eslint-disable-line import/no-extraneous-dependencies
const sinon = require('sinon');

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
      `_grant=; path=${this.url}; expires=${expired.toGMTString()}; httponly`,
      `_grant.sig=; path=${this.url}; expires=${expired.toGMTString()}; httponly`,
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
    sinon.stub(this.provider.Session, 'find').resolves();

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
    if (this.provider.Session.find.restore) this.provider.Session.find.restore();
    if (this.provider.interactionDetails.restore) this.provider.interactionDetails.restore();
    if (this.provider.interactionFinished.restore) this.provider.interactionFinished.restore();
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
        .expect(new RegExp(`action="${this.url}/submit"`))
        .expect(new RegExp('name="view" value="login"'))
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
        .expect(new RegExp(`action="${this.url}/submit"`))
        .expect(new RegExp('name="view" value="interaction"'))
        .expect(/Authorize/);
    });

    handlesInteractionSessionErrors();
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
      return this.agent.post(`${this.url}/submit`)
        .send({
          view: 'login',
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
      return this.agent.post(`${this.url}/submit`)
        .send({
          view: 'interaction',
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
    if (this.provider.Session.find.restore) this.provider.Session.find.restore();
  });

  function setup(grant, result) {
    const cookies = [];

    const interaction = new this.provider.Session('resume', {});
    const session = new this.provider.Session('sess', {});
    const keys = new KeyGrip(i(this.provider).configuration('cookies.keys'));

    expect(grant).to.be.ok;

    const cookie = `_grant=resume; path=/auth/resume; expires=${expire.toGMTString()}; httponly`;
    cookies.push(cookie);
    let [pre, ...post] = cookie.split(';');
    cookies.push([`_grant.sig=${keys.sign(pre)}`, ...post].join(';'));
    Object.assign(interaction, { params: grant });

    const sessionCookie = `_session=sess; path=/; expires=${expire.toGMTString()}; httponly`;
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

    it('needs to find the session to resume', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      sinon.stub(this.provider.Session, 'find').resolves();

      return this.agent.get('/auth/resume')
        .expect(400)
        .expect(/interaction session not found/);
    });
  });

  context('login results', () => {
    it('should redirect to client with error if interaction did not resolve in a session', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('login_required'))
        .expect(auth.validateErrorDescription('End-User authentication is required'));
    });

    it('should process newly established permanent sessions', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
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

    it('should process newly established temporary sessions', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
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
  });

  context('consent results', () => {
    it('when scope includes offline_access', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        prompt: 'consent',
        scope: 'openid offline_access',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
          remember: true,
        },
        consent: {},
      });

      let authorizationCode;

      this.provider.once('token.issued', (code) => {
        authorizationCode = code;
      });

      return this.agent.get('/auth/resume')
        .expect(() => {
          this.provider.removeAllListeners('token.issued');
        })
        .expect(() => {
          expect(authorizationCode).to.be.ok;
          expect(authorizationCode).to.have.property('scope', 'openid offline_access');
        });
    });

    it('if not resolved returns consent_required error', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'consent',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
          remember: true,
        },
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('consent_required'))
        .expect(auth.validateErrorDescription('prompt consent was not resolved'));
    });

    describe('custom interaction errors', () => {
      it('custom interactions can fail too', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          custom: 'foo',
        });

        setup.call(this, auth, {
          login: {
            account: uuid(),
            remember: true,
          },
          consent: {},
        });

        return this.agent.get('/auth/resume')
          .expect(302)
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('error_foo'))
          .expect(auth.validateErrorDescription('error_description_foo'));
      });
    });

    describe('rejectedScopes', () => {
      it('allows for scopes to be rejected', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid profile',
        });

        setup.call(this, auth, {
          login: {
            account: uuid(),
            remember: true,
          },
          consent: {
            rejectedScopes: ['profile'],
          },
        });

        let authorizationCode;

        this.provider.once('token.issued', (code) => {
          authorizationCode = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            this.provider.removeAllListeners('token.issued');
          })
          .expect(() => {
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid');
          });
      });

      it('cannot reject openid scope', async function () {
        const spy = sinon.spy();
        this.provider.once('server_error', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          prompt: 'consent',
        });

        setup.call(this, auth, {
          login: {
            account: uuid(),
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
        const error = spy.firstCall.args[0];
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

        setup.call(this, auth, {
          login: {
            account: uuid(),
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
        const error = spy.firstCall.args[0];
        expect(error).to.be.an.instanceof(Error);
        expect(error).to.have.property('message', 'expected Array or Set');
      });
    });

    describe('rejectedClaims', () => {
      it('allows for claims to be rejected', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid profile',
        });

        setup.call(this, auth, {
          login: {
            account: uuid(),
            remember: true,
          },
          consent: {
            rejectedClaims: ['nickname'],
          },
        });

        let authorizationCode;

        this.provider.once('token.issued', (code) => {
          authorizationCode = code;
        });

        return this.agent.get('/auth/resume')
          .expect(() => {
            this.provider.removeAllListeners('token.issued');
          })
          .expect(() => {
            expect(authorizationCode).to.be.ok;
            expect(authorizationCode).to.have.property('scope', 'openid profile');
            expect(authorizationCode).to.have.deep.property('claims', { rejected: ['nickname'] });
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

          setup.call(this, auth, {
            login: {
              account: uuid(),
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
          const error = spy.firstCall.args[0];
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

        setup.call(this, auth, {
          login: {
            account: uuid(),
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
        const error = spy.firstCall.args[0];
        expect(error).to.be.an.instanceof(Error);
        expect(error).to.have.property('message', 'expected Array or Set');
      });
    });
  });

  context('meta results', () => {
    it('should process and store meta-informations provided alongside login', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'fragment',
        scope: 'openid',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
          remember: true,
        },
        meta: {
          scope: 'openid',
        },
      });

      return this.agent.get('/auth/resume')
        .expect(() => {
          const meta = this.getSession({ instantiate: true }).metaFor(config.client.client_id);
          expect(meta).to.be.ok;
          expect(meta).to.have.property('scope');
        });
    });
  });

  context('interaction errors', () => {
    it('should abort an interaction when given an error result object (no description)', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth, {
        error: 'access_denied',
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateError('access_denied'))
        .expect(auth.validateErrorDescription(''));
    });

    it('should abort an interaction when given an error result object (with state)', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        state: 'bf458-00aa3',
      });

      setup.call(this, auth, {
        error: 'access_denied',
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateError('access_denied'))
        .expect(auth.validateErrorDescription(''));
    });

    it('should abort an interaction when given an error result object (with description)', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth, {
        error: 'access_denied',
        error_description: 'scope out of reach',
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateError('access_denied'))
        .expect(auth.validateErrorDescription('scope out of reach'));
    });

    it('should abort an interaction when given an error result object (custom error)', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth, {
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

  context('custom prompts', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('should fail if they are not resolved', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'custom',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
          remember: true,
        },
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('interaction_required'))
        .expect(auth.validateErrorDescription('prompt custom was not resolved'));
    });
  });
});
