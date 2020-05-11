/* eslint-disable no-underscore-dangle */
const { expect } = require('chai');
const KeyGrip = require('keygrip'); // eslint-disable-line import/no-extraneous-dependencies
const sinon = require('sinon').createSandbox();

const nanoid = require('../../lib/helpers/nanoid');
const bootstrap = require('../test_helper');
const epochTime = require('../../lib/helpers/epoch_time');
const { generate } = require('../../lib/helpers/user_codes');

const { any } = sinon.match;

const expire = new Date();
expire.setDate(expire.getDate() + 1);

let grantId;
let userCode;
let path;

describe('device interaction resume /device/:user_code/:uid/', () => {
  before(bootstrap(__dirname));

  beforeEach(function () {
    grantId = nanoid();
    userCode = generate('base-20', '***-***-***');
    path = this.suitePath(`/device/${userCode}/${grantId}`);
  });

  afterEach(sinon.restore);

  function setup(auth, result, sessionData) {
    expect(auth).to.be.ok;

    const cookies = [];

    const params = {
      client_id: 'client',
      ...auth,
    };

    const session = new this.provider.Session({ jti: 'sess', ...sessionData });
    const interaction = new this.provider.Interaction(grantId, { session });
    const keys = new KeyGrip(i(this.provider).configuration('cookies.keys'));
    const code = new this.provider.DeviceCode({
      params,
      clientId: 'client',
      grantId,
      userCode,
    });

    const cookie = `_interaction_resume=${grantId}; path=${path}; expires=${expire.toGMTString()}; httponly`;
    cookies.push(cookie);
    let [pre, ...post] = cookie.split(';');
    cookies.push([`_interaction_resume.sig=${keys.sign(pre)}`, ...post].join(';'));
    Object.assign(interaction, { params });

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
      code.save(),
      interaction.save(),
      session.save(),
    ]);
  }

  bootstrap.passInteractionChecks('native_client_prompt', () => {
    context('general', () => {
      it('needs the resume cookie to be present, else renders an err', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        await setup.call(this, {
          scope: 'openid',
        }, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {},
        });

        // force an invalid sig, hence the framework not loading the cookie
        this.agent._saveCookies.bind(this.agent)({
          headers: {
            'set-cookie': `_interaction_resume.sig=; path=${path}; httpOnly`,
          },
        });

        await this.agent.get(path)
          .accept('text/html')
          .expect(400)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.name).to.equal('SessionNotFound');
          expect(err.error_description).to.equal('authorization request has expired');
          return true;
        }));
      });

      it('needs to find the session to resume', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(this, auth);

        sinon.stub(this.provider.Interaction, 'find').resolves();

        await this.agent.get(path)
          .accept('text/html')
          .expect(400)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.name).to.equal('SessionNotFound');
          expect(err.error_description).to.equal('interaction session not found');
          return true;
        }));
      });

      it('needs to find the code to resume', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(this, auth);

        sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves();

        await this.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.name).to.equal('NotFoundError');
          expect(err.message).to.equal('the code was not found');
          return true;
        }));
      });

      it('checks code is not expired', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(this, auth);

        sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId, isExpired: true });

        await this.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.name).to.equal('ExpiredError');
          expect(err.message).to.equal('the code has expired');
          return true;
        }));
      });

      it('checks code is not used already (1/2)', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(this, auth);

        sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId, accountId: 'foo' });

        await this.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.name).to.equal('AlreadyUsedError');
          expect(err.message).to.equal('code has already been used');
          return true;
        }));
      });

      it('checks code is not used already (2/2)', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(this, auth);

        sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId, error: 'access_denied' });

        await this.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.name).to.equal('AlreadyUsedError');
          expect(err.message).to.equal('code has already been used');
          return true;
        }));
      });

      it('checks for mismatches in resume and code grants', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(this, auth);

        sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId: 'foo', save: sinon.stub().resolves() });

        await this.agent.get(path)
          .accept('text/html')
          .expect(400)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.name).to.equal('InvalidRequest');
          expect(err.error).to.equal('invalid_request');
          expect(err.error_description).to.equal('grantId mismatch');
          return true;
        }));
      });
    });

    context('login results', () => {
      it('should process newly established permanent sessions (default)', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

        await setup.call(this, {
          scope: 'openid',
        }, {
          login: {
            account: nanoid(),
          },
          consent: {},
        });

        await this.agent.get(path)
          .accept('text/html')
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(200)
          .expect('set-cookie', /expires/) // expect a permanent cookie
          .expect(() => {
            expect(this.getSession()).to.be.ok.and.not.have.property('transient');
          });

        const code = await this.provider.DeviceCode.findByUserCode(userCode);
        expect(code).to.have.property('accountId');
      });

      it('should process newly established permanent sessions (explicit)', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

        await setup.call(this, {
          scope: 'openid',
        }, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {},
        });

        await this.agent.get(path)
          .accept('text/html')
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(200)
          .expect('set-cookie', /expires/) // expect a permanent cookie
          .expect(() => {
            expect(this.getSession()).to.be.ok.and.not.have.property('transient');
          });

        const code = await this.provider.DeviceCode.findByUserCode(userCode);
        expect(code).to.have.property('accountId');
      });

      it('should process newly established temporary sessions', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

        await setup.call(this, {
          scope: 'openid',
        }, {
          login: {
            account: nanoid(),
            remember: false,
          },
          consent: {},
        });

        await this.agent.get(path)
          .accept('text/html')
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(200)
          .expect(() => {
            expect(this.getSession()).to.be.ok.and.have.property('transient');
          });

        const code = await this.provider.DeviceCode.findByUserCode(userCode);
        expect(code).to.have.property('accountId');
      });

      it('should trigger logout when the session subject changes', async function () {
        const auth = new this.AuthorizationRequest({
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

        let state;

        await this.agent.get(path)
          .expect(200)
          .expect('content-type', 'text/html; charset=utf-8')
          .expect(/document.addEventListener\('DOMContentLoaded', function \(\) { document.forms\[0\].submit\(\) }\);/)
          .expect(/<input type="hidden" name="logout" value="yes"\/>/)
          .expect(({ text }) => {
            ({ state } = this.getSession());
            expect(state).to.have.property('clientId', 'client');
            expect(state).to.have.property('postLogoutRedirectUri').that.matches(new RegExp(`${path}$`));
            expect(text).to.match(new RegExp(`input type="hidden" name="xsrf" value="${state.secret}"`));
          })
          .expect(/<form method="post" action=".+\/session\/end\/confirm">/);

        expect(await this.provider.Interaction.find(grantId)).to.be.ok;

        await this.agent.post('/session/end/confirm')
          .send({
            xsrf: state.secret,
            logout: 'yes',
          })
          .type('form')
          .expect(302)
          .expect('location', state.postLogoutRedirectUri);

        await this.agent.get(state.postLogoutRedirectUri.replace(this.provider.issuer, ''))
          .expect(200);
      });
    });

    context('consent results', () => {
      it('when scope includes offline_access', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

        await setup.call(this, {
          scope: 'openid offline_access',
        }, {
          login: {
            account: nanoid(),
            remember: true,
          },
          consent: {},
        });

        await this.agent.get(path)
          .accept('text/html')
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(200);

        const code = await this.provider.DeviceCode.findByUserCode(userCode);
        expect(code).to.have.property('accountId');
        expect(code).to.have.property('scope', 'openid offline_access');
      });
    });

    context('interaction errors', () => {
      it('should abort an interaction when given an error result object', async function () {
        const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

        await setup.call(this, {
          scope: 'openid',
        }, {
          error: 'access_denied',
          error_description: 'scope out of reach',
        });

        await this.agent.get(path)
          .accept('text/html')
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
          .expect(/<p class="red">The Sign-in request was interrupted<\/p>/);

        expect(spy.calledOnce).to.be.true;
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          expect(err.message).to.equal('the interaction was aborted');
          return true;
        }));
      });
    });
  });
});
