const sinon = require('sinon');
const { expect } = require('chai');
const timekeeper = require('timekeeper');

const bootstrap = require('../test_helper');

const { any } = sinon.match;
const route = '/device';

describe('GET code_verification endpoint', () => {
  before(bootstrap(__dirname)); // agent

  describe('when accessed without user_code in query (verification_uri)', () => {
    it('renders 200 OK end-user form with csrf', function () {
      return this.agent.get(route)
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(() => {
          const { device: { secret } } = this.getSession();
          expect(secret).to.be.a('string');
        })
        .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/);
    });
  });

  describe('when accessed with user_code in query (verification_uri_complete)', () => {
    it('renders 200 OK self-submitting form with csrf and the value from uri', function () {
      let secret;

      return this.agent.get(route)
        .query({ user_code: '123-456-789' })
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/<body onload="javascript:document\.forms\[0]\.submit\(\)"/)
        .expect(({ text }) => {
          ({ device: { secret } } = this.getSession());
          expect(text).to.match(new RegExp(`input type="hidden" name="xsrf" value="${secret}"`));
        })
        .expect(/<form method="post" action="\/device">/)
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
  before(bootstrap(__dirname)); // agent
  before(function () { return this.login(); });
  afterEach(() => timekeeper.reset());

  const xsrf = 'foo';

  beforeEach(function () {
    this.getSession().device = { secret: xsrf };
  });
  afterEach(function () {
    this.provider.removeAllListeners('code_verification.error');
    try {
      i(this.provider).configuration().userCodeInputSource.restore();
    } catch (err) {}
    try {
      i(this.provider).configuration().userCodeConfirmSource.restore();
    } catch (err) {}
    try {
      this.provider.Client.find.restore();
    } catch (err) {}
  });

  it('renders a confirmation page', async function () {
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeConfirmSource');
    const deviceInfo = {
      ip: '127.0.0.1',
      userAgent: 'foo',
    };

    await new this.provider.DeviceCode({
      clientId: 'client',
      userCode: 'foo-code',
      deviceInfo,
    }).save();

    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'foo-code',
      })
      .type('form')
      .expect(200)
      .expect(/<form id="op\.deviceConfirmForm" method="post" action="\/device">/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, sinon.match((client) => {
      expect(client.clientId).to.equal('client');
      return true;
    }), deviceInfo);
  });

  it('re-renders on no submitted code', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

    await this.agent.post(route)
      .send({ xsrf })
      .type('form')
      .expect(200)
      .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/)
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
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');

    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'foo-not-found',
      })
      .type('form')
      .expect(200)
      .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/)
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
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'foo-expired',
    }).save();

    timekeeper.travel(Date.now() + (((10 * 60) + 10) * 1000));
    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'foo-expired',
      })
      .type('form')
      .expect(200)
      .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/)
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
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'foo-consumed',
      accountId: 'account',
    }).save();

    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'foo-consumed',
      })
      .type('form')
      .expect(200)
      .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/)
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
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'foo-not-found-client',
      clientId: 'client',
    }).save();

    sinon.stub(this.provider.Client, 'find').callsFake(async () => { });
    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'foo-not-found-client',
      })
      .type('form')
      .expect(400)
      .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/)
      .expect(/<p class="red">There was an error processing your request<\/p>/);

    expect(spy.calledOnce).to.be.true;
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      expect(err.name).to.equal('InvalidClient');
      return true;
    }));

    expect(errSpy.calledOnce).to.be.true;
  });

  it('re-renders on !ctx.oidc.session.device', async function () {
    const errSpy = sinon.spy();
    this.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'foo-csrf-1',
    }).save();

    delete this.getSession().device;
    await this.agent.post(route)
      .send({
        xsrf,
        user_code: 'foo-csrf-1',
      })
      .type('form')
      .expect(400)
      .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/)
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
    const spy = sinon.spy(i(this.provider).configuration(), 'userCodeInputSource');
    await new this.provider.DeviceCode({
      userCode: 'foo-csrf-2',
    }).save();

    await this.agent.post(route)
      .send({
        xsrf: 'invalid-csrf',
        user_code: 'foo-csrf-foo',
      })
      .type('form')
      .expect(400)
      .expect(/<form id="op\.deviceInputForm" method="post" action="\/device">/)
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
  before(bootstrap(__dirname)); // agent
  before(function () { return this.login(); });
  afterEach(() => timekeeper.reset());

  const xsrf = 'foo';

  beforeEach(function () {
    this.getSession().device = { secret: xsrf };
  });

  it('renders a confirmation and assigns ', async function () {
    const spy = sinon.spy(i(this.provider).configuration(), 'deviceCodeSuccess');

    let code = await new this.provider.DeviceCode({
      clientId: 'client',
      userCode: 'foo',
      params: {
        client_id: 'client',
        claims: JSON.stringify({ userinfo: { email: null } }),
      },
    }).save();

    await this.agent.post(route)
      .send({
        xsrf,
        confirm: 'yes',
        user_code: 'foo',
      })
      .type('form')
      .expect(200);

    code = await this.provider.DeviceCode.find(code);

    const session = this.getSession();

    expect(code).to.have.property('accountId', session.account);
    expect(code).to.have.property('authTime', session.loginTs);
    expect(code).to.have.property('claims').that.eqls({ userinfo: { email: null } });

    expect(spy.calledOnce).to.be.true;
  });
});
