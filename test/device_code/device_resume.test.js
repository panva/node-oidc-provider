/* eslint-disable no-underscore-dangle */
const { expect } = require('chai');
const uuid = require('uuid/v4');
const KeyGrip = require('keygrip'); // eslint-disable-line import/no-extraneous-dependencies
const sinon = require('sinon');

const bootstrap = require('../test_helper');
const epochTime = require('../../lib/helpers/epoch_time');
const { generate } = require('../../lib/helpers/user_codes');

const { any } = sinon.match;

const expire = new Date();
expire.setDate(expire.getDate() + 1);

let grantId;
let userCode;
let path;

describe('device interaction resume /device/:user_code/:grant/', () => {
  before(bootstrap(__dirname));

  beforeEach(() => {
    grantId = uuid();
    userCode = generate('base-20', '***-***-***');
    path = `/device/${userCode}/${grantId}`;
  });

  afterEach(function () {
    if (this.provider.Session.find.restore) {
      this.provider.Session.find.restore();
    }
    if (this.provider.interactionDetails.restore) {
      this.provider.interactionDetails.restore();
    }
    if (this.provider.DeviceCode.findByUserCode.restore) {
      this.provider.DeviceCode.findByUserCode.restore();
    }
    if (i(this.provider).configuration().deviceCodeSuccess.restore) {
      i(this.provider).configuration().deviceCodeSuccess.restore();
    }
    if (i(this.provider).configuration().userCodeInputSource.restore) {
      i(this.provider).configuration().userCodeInputSource.restore();
    }
  });

  function setup(auth, result) {
    expect(auth).to.be.ok;

    const cookies = [];

    const params = {
      client_id: 'client',
      ...auth,
    };

    const interaction = new this.provider.Session(grantId, {});
    const session = new this.provider.Session('sess', {});
    const keys = new KeyGrip(i(this.provider).configuration('cookies.keys'));
    const code = new this.provider.DeviceCode({
      params,
      clientId: 'client',
      grantId,
      userCode,
    });

    const cookie = `_grant=${grantId}; path=${path}; expires=${expire.toGMTString()}; httponly`;
    cookies.push(cookie);
    let [pre, ...post] = cookie.split(';');
    cookies.push([`_grant.sig=${keys.sign(pre)}`, ...post].join(';'));
    Object.assign(interaction, { params });

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
      code.save(),
      interaction.save(),
      session.save(),
    ]);
  }

  context('general', () => {
    it('needs the resume cookie to be present, else renders an err', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      await this.agent.get(path)
        .accept('text/html')
        .expect(400)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.name).to.equal('SessionNotFound');
        expect(err.error_description).to.equal('authorization request has expired');
        return true;
      }));
    });

    it('needs to find the session to resume', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      sinon.stub(this.provider.Session, 'find').resolves();

      await this.agent.get(path)
        .accept('text/html')
        .expect(400)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.name).to.equal('SessionNotFound');
        expect(err.error_description).to.equal('interaction session not found');
        return true;
      }));
    });

    it('needs to find the code to resume', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves();

      await this.agent.get(path)
        .accept('text/html')
        .expect(200)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.name).to.equal('NotFoundError');
        expect(err.message).to.equal('the code was not found');
        return true;
      }));
    });

    it('checks code is not expired', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId, isExpired: true });

      await this.agent.get(path)
        .accept('text/html')
        .expect(200)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.name).to.equal('ExpiredError');
        expect(err.message).to.equal('the code has expired');
        return true;
      }));
    });

    it('checks code is not used already (1/2)', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId, accountId: 'foo' });

      await this.agent.get(path)
        .accept('text/html')
        .expect(200)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.name).to.equal('AlreadyUsedError');
        expect(err.message).to.equal('code has already been used');
        return true;
      }));
    });

    it('checks code is not used already (2/2)', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId, error: 'access_denied' });

      await this.agent.get(path)
        .accept('text/html')
        .expect(200)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.name).to.equal('AlreadyUsedError');
        expect(err.message).to.equal('code has already been used');
        return true;
      }));
    });

    it('checks for mismatches in resume and code grants', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      setup.call(this, auth);

      sinon.stub(this.provider.DeviceCode, 'findByUserCode').resolves({ grantId: 'foo', save: sinon.stub().resolves() });

      await this.agent.get(path)
        .accept('text/html')
        .expect(400)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
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
    it('should re-render if there was no session created', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      setup.call(this, {
        scope: 'openid',
      });

      await this.agent.get(path)
        .accept('text/html')
        .expect(400)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.message).to.equal('login_required');
        expect(err.error_description).to.equal('End-User authentication is required');
        return true;
      }));
    });

    it('should process newly established permanent sessions', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'deviceCodeSuccess');

      setup.call(this, {
        scope: 'openid',
      }, {
        login: {
          account: uuid(),
          remember: true,
        },
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
      const spy = sinon.spy(i(this.provider).configuration(), 'deviceCodeSuccess');

      setup.call(this, {
        scope: 'openid',
      }, {
        login: {
          account: uuid(),
        },
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
  });

  context('consent results', () => {
    it('when scope includes offline_access', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'deviceCodeSuccess');

      setup.call(this, {
        scope: 'openid offline_access',
      }, {
        login: {
          account: uuid(),
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

    it('if not resolved returns consent_required error', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      setup.call(this, {
        scope: 'openid',
        prompt: 'consent',
      }, {
        login: {
          account: uuid(),
          remember: true,
        },
      });

      await this.agent.get(path)
        .accept('text/html')
        .expect(400)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.message).to.equal('consent_required');
        expect(err.error_description).to.equal('prompt consent was not resolved');
        return true;
      }));
    });
  });

  context('interaction errors', () => {
    it('should abort an interaction when given an error result object', async function () {
      const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

      setup.call(this, {
        scope: 'openid',
      }, {
        error: 'access_denied',
        error_description: 'scope out of reach',
      });

      await this.agent.get(path)
        .accept('text/html')
        .expect(400)
        .expect(/<form id="op\.deviceInputForm" novalidate method="post" action="\/device">/)
        .expect(/<p class="red">There was an error processing your request<\/p>/);

      expect(spy.calledOnce).to.be.true;
      sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
        expect(err.message).to.equal('access_denied');
        expect(err.error_description).to.equal('scope out of reach');
        return true;
      }));
    });
  });
});
