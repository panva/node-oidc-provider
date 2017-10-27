/* eslint-disable no-underscore-dangle */

const uuid = require('uuid/v4');
const bootstrap = require('../test_helper');
const config = require('./interaction.config.js');

const expire = new Date();
expire.setDate(expire.getDate() + 1);

const { expect } = require('chai');

describe('devInteractions', () => {
  context('renders login', () => {
    before(bootstrap(__dirname));
    before(function () {
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
  });

  context('render interaction', () => {
    before(bootstrap(__dirname));
    before(function () { return this.login(); });
    before(function () {
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
  });

  context('submit login', () => {
    before(bootstrap(__dirname));
    before(function () {
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
  });

  context('submit interaction', () => {
    before(bootstrap(__dirname));
    before(function () { return this.login(); });
    before(function () {
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
  });
});

describe('resume after interaction', () => {
  before(bootstrap(__dirname));

  before(function () {
    i(this.provider).configuration('prompts').push('custom');
  });

  function setup(grant, result) {
    const cookies = [];

    const sess = new this.provider.Session('resume', {});

    if (grant) {
      cookies.push(`_grant=resume; path=/auth/resume; expires=${expire.toGMTString()}; httponly`);
      Object.assign(sess, { params: grant });
    }

    if (result) {
      Object.assign(sess, { result });
    }

    this.agent._saveCookies.bind(this.agent)({
      headers: {
        'set-cookie': cookies,
      },
    });

    return sess.save();
  }

  context('general', () => {
    it('needs the results to be present, else renders an err', function () {
      return this.agent.get('/auth/resume')
        .expect(400)
        .expect(/authorization request has expired/);
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
        scope: 'openid',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
          remember: true,
        },
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect('set-cookie', /expires/) // expect a permanent cookie
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(() => {
          expect(this.getSession()).to.be.ok.and.not.have.property('transient');
        });
    });

    it('should process newly established temporary sessions', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
        },
      });

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect('set-cookie', /^_session=((?!expires).)+,/) // expect a transient session cookie
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state']))
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

    it('should use the scope from resume cookie if provided', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth, {
        login: {
          account: uuid(),
          remember: true,
        },
        consent: {
          scope: 'openid profile',
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
  });

  context('meta results', () => {
    it('should process and store meta-informations provided alongside login', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
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

  context('custom prompts', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('should fail if they are not resolved', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'custom',
      });

      setup.call(this, auth);

      return this.agent.get('/auth/resume')
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('interaction_required'))
        .expect(auth.validateErrorDescription('prompt custom was not resolved'));
    });
  });
});
