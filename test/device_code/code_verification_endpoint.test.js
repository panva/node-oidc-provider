const sinon = require('sinon').createSandbox();
const { expect } = require('chai');
const timekeeper = require('timekeeper');

const bootstrap = require('../test_helper');

const { any } = sinon.match;
const route = '/device';

describe('GET code_verification endpoint', () => {
  before(bootstrap(__dirname));

  describe('when accessed without user_code in query (verification_uri)', () => {
    it('renders 200 OK end-user form with csrf', function () {
      return this.agent.get(route)
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(() => {
          const { state: { secret } } = this.getSession();
          expect(secret).to.be.a('string');
        })
        .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`));
    });
  });

  describe('when accessed with user_code in query (verification_uri_complete)', () => {
    it('renders 200 OK self-submitting form with csrf and the value from uri', function () {
      let secret;

      return this.agent.get(route)
        .query({ user_code: '123-456-789' })
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/document.addEventListener\('DOMContentLoaded', function \(\) { document.forms\[0\].submit\(\) }\);/)
        .expect(({ text }) => {
          ({ state: { secret } } = this.getSession());
          expect(text).to.match(new RegExp(`input type="hidden" name="xsrf" value="${secret}"`));
        })
        .expect(new RegExp(`<form method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
        .expect(/<input type="hidden" name="user_code" value="123-456-789"\/>/);
    });

    it('escapes the user_code values', function () {
      return this.agent.get(route)
        .query({ user_code: '&<>"\'123-456-789' })
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/<input type="hidden" name="user_code" value="&amp;&lt;&gt;&quot;&#39;123-456-789"\/>/);
    });
  });
});

describe('POST code_verification endpoint w/o verification', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login(); });
  afterEach(() => timekeeper.reset());

  const xsrf = 'foo';

  beforeEach(function () {
    this.getSession().state = { secret: xsrf };
  });

  afterEach(function () {
    this.provider.removeAllListeners('code_verification.error');
    sinon.restore();
  });

  it('renders a confirmation page', async function () {
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeConfirmSource');
    const deviceInfo = {
      ip: '127.0.0.1',
      ua: 'foo',
    };

    await new this.provider.DeviceCode({
      clientId: 'client',
      userCode: 'FOOCODE',
      deviceInfo,
    }).save();

    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-CODE',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceConfirmForm" method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`));

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, sinon.match((client) => {
      expect(client.clientId).to.equal('client');
      return true;
    }), deviceInfo);
  });

  it('re-renders on no submitted code', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

    await this.agent.post(route)
      .send({ xsrf })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('NoCodeError');
      return true;
    }));

    expect(errSpy).to.have.property('called', false);
  });

  it('re-renders on not found code', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-NOT-FOUND',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('NotFoundError');
      return true;
    }));

    expect(errSpy).to.have.property('called', false);
  });

  it('re-renders on found but expired code', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'FOOEXPIRED',
    }).save();

    timekeeper.travel(Date.now() + (((10 * 60) + 10) * 1000));
    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-EXPIRED',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('ExpiredError');
      return true;
    }));

    expect(errSpy).to.have.property('called', false);
  });

  it('re-renders on found but already user code', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'FOOCONSUMED',
      accountId: 'account',
    }).save();

    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-CONSUMED',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('AlreadyUsedError');
      return true;
    }));

    expect(errSpy).to.have.property('called', false);
  });

  it('re-renders on invalid client', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'FOONOTFOUNDCLIENT',
      clientId: 'client',
    }).save();

    sinon.stub(this.provider.Client, 'find').callsFake(async () => { });
    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-NOT-FOUND-CLIENT',
      })
      .type('form')
      .expect(400)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
      .expect(/<p class="red">There was an error processing your request<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('InvalidClient');
      return true;
    }));

    expect(errSpy.calledOnce).to.be.true;
  });

  it('re-renders on !ctx.oidc.session.state', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'FOOCSRF1',
    }).save();

    delete this.getSession().state;
    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-CSRF-1',
      })
      .type('form')
      .expect(400)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
      .expect(/<p class="red">There was an error processing your request<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('InvalidRequest');
      expect(err.error_description).to.equal('could not find device form details');
      return true;
    }));

    expect(errSpy.calledOnce).to.be.true;
  });

  it('re-renders on invalid csrf', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'FOOCSRF2',
    }).save();

    await this.agent.post(route)
      .send({
        xsrf: 'invalid-csrf',
        user_code: 'FOO-CSRF-FOO',
      })
      .type('form')
      .expect(400)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${this.suitePath('/device')}">`))
      .expect(/<p class="red">There was an error processing your request<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('InvalidRequest');
      expect(err.error_description).to.equal('xsrf token invalid');
      return true;
    }));

    expect(errSpy.calledOnce).to.be.true;
  });
});

describe('POST code_verification endpoint w/ verification', () => {
  before(bootstrap(__dirname));
  before(function () {
    return this.login({
      scope: 'openid email',
      rejectedClaims: ['email_verified'],
    });
  });
  afterEach(timekeeper.reset);
  afterEach(sinon.restore);

  const xsrf = 'foo';

  beforeEach(function () {
    this.getSession().state = { secret: xsrf };
  });

  bootstrap.passInteractionChecks('native_client_prompt', 'claims_missing', () => {
    it('accepts an abort command', async function () {
      const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'userCodeInputSource');

      let code = await new this.provider.DeviceCode({
        grantId: this.getSession({ instantiate: true }).grantIdFor('client'),
        clientId: 'client',
        userCode: 'FOO',
        params: {
          scope: 'openid email',
          client_id: 'client',
          claims: JSON.stringify({ userinfo: { email: null } }),
          resource: 'urn:foo:bar',
        },
      }).save();

      await this.agent.post(route)
        .send({
          xsrf,
          abort: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200)
        .expect(/The Sign-in request was interrupted/);

      code = await this.provider.DeviceCode.find(code);

      expect(code).not.to.have.property('accountId');
      expect(code).to.have.property('error', 'access_denied');
      expect(code).to.have.property('errorDescription', 'End-User aborted interaction');

      expect(spy.calledOnce).to.be.true;
    });

    it('renders a confirmation and assigns', async function () {
      const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

      let code = await new this.provider.DeviceCode({
        grantId: this.getSession({ instantiate: true }).grantIdFor('client'),
        clientId: 'client',
        userCode: 'FOO',
        params: {
          scope: 'openid email',
          client_id: 'client',
          claims: JSON.stringify({ userinfo: { email: null } }),
          resource: 'urn:foo:bar',
        },
      }).save();

      await this.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200);

      code = await this.provider.DeviceCode.find(code);

      const session = this.getSession();

      expect(code).not.to.have.property('sid');
      expect(code).to.have.property('accountId', session.account);
      expect(code).to.have.property('authTime', session.loginTs);
      expect(code).to.have.property('scope', 'openid email');
      expect(code).to.have.property('claims').that.eqls({ userinfo: { email: null }, rejected: ['email_verified'] });
      expect(code).to.have.property('resource', 'urn:foo:bar');

      expect(spy.calledOnce).to.be.true;
    });

    it('renders a confirmation and assigns (incl. sid because of client configuration)', async function () {
      const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

      let code = await new this.provider.DeviceCode({
        grantId: this.getSession({ instantiate: true }).grantIdFor('client-backchannel'),
        clientId: 'client-backchannel',
        userCode: 'FOO',
        params: {
          scope: 'openid',
          client_id: 'client-backchannel',
        },
      }).save();

      await this.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200);

      code = await this.provider.DeviceCode.find(code);

      expect(code).to.have.property('sid');
      expect(spy.calledOnce).to.be.true;
    });

    it('renders a confirmation and assigns (incl. sid because of claims)', async function () {
      const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

      let code = await new this.provider.DeviceCode({
        grantId: this.getSession({ instantiate: true }).grantIdFor('client'),
        clientId: 'client',
        userCode: 'FOO',
        params: {
          scope: 'openid',
          client_id: 'client',
          claims: JSON.stringify({ id_token: { sid: null } }),
        },
      }).save();

      await this.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200);

      code = await this.provider.DeviceCode.find(code);

      expect(code).to.have.property('sid');
      expect(spy.calledOnce).to.be.true;
    });

    it('allows for punctuation to be included and characters to be downcased', async function () {
      const spy = sinon.spy(i(this.provider).configuration('features.deviceFlow'), 'successSource');

      let code = await new this.provider.DeviceCode({
        grantId: this.getSession({ instantiate: true }).grantIdFor('client'),
        clientId: 'client',
        userCode: 'FOOBAR',
        params: {
          scope: 'openid email',
          client_id: 'client',
          claims: JSON.stringify({ userinfo: { email: null } }),
        },
      }).save();

      await this.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'f o o b a r',
        })
        .type('form')
        .expect(200);

      code = await this.provider.DeviceCode.find(code);

      const session = this.getSession();

      expect(code).to.have.property('accountId', session.account);
      expect(code).to.have.property('authTime', session.loginTs);
      expect(code).to.have.property('scope', 'openid email');
      expect(code).to.have.property('claims').that.eqls({ userinfo: { email: null }, rejected: ['email_verified'] });

      expect(spy.calledOnce).to.be.true;
    });
  });
});
