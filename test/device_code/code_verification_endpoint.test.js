import { describe, before, it, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';
import timekeeper from 'timekeeper';

import bootstrap, { passInteractionChecks } from '../test_helper.js';

const sinon = createSandbox();

const { any } = sinon.match;
const route = '/device';

describe('GET code_verification endpoint', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('when accessed without user_code in query (verification_uri)', () => {
    const fixture1 = Object.create(fixture);

    it('renders 200 OK end-user form with csrf', { timeout: 3000 }, () => fixture1.agent.get(route)
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(() => {
          const { state: { secret } } = fixture1.getSession();
          assert.equal(typeof secret, 'string');
        })
        .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture1.suitePath('/device')}">`)));
  });

  describe('when accessed with user_code in query (verification_uri_complete)', () => {
    const fixture2 = Object.create(fixture);

    it('renders 200 OK self-submitting form with csrf and the value from uri', { timeout: 3000 }, () => {
      let secret;

      return fixture2.agent.get(route)
        .query({ user_code: '123-456-789' })
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/document.addEventListener\('DOMContentLoaded', function \(\) { document.forms\[0\].submit\(\) }\);/)
        .expect(({ text }) => {
          ({ state: { secret } } = fixture2.getSession());
          assert.match(text, new RegExp(`input type="hidden" name="xsrf" value="${secret}"`));
        })
        .expect(new RegExp(`<form method="post" action="http://127.0.0.1:\\d+${fixture2.suitePath('/device')}">`))
        .expect(/<input type="hidden" name="user_code" value="123-456-789"\/>/);
    });

    it('escapes the user_code values', { timeout: 3000 }, () => fixture2.agent.get(route)
        .query({ user_code: '&<>"\'123-456-789' })
        .expect(200)
        .expect('content-type', 'text/html; charset=utf-8')
        .expect(/<input type="hidden" name="user_code" value="&amp;&lt;&gt;&quot;&#39;123-456-789"\/>/));
  });
});

describe('POST code_verification endpoint w/o verification', () => {
  const fixture3 = {};

  before(bootstrap(import.meta.url, fixture3), { timeout: 3000 });
  before(() => fixture3.login(), { timeout: 3000 });
  afterEach(() => timekeeper.reset(), { timeout: 3000 });

  const xsrf = 'foo';

  beforeEach(() => {
    fixture3.getSession().state = { secret: xsrf };
  }, { timeout: 3000 });

  afterEach(() => {
    fixture3.provider.removeAllListeners('code_verification.error');
    sinon.restore();
  }, { timeout: 3000 });

  it('renders a confirmation page', { timeout: 3000 }, async () => {
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeConfirmSource');
    const deviceInfo = {
      ip: '127.0.0.1',
      ua: 'foo',
    };

    await new fixture3.provider.DeviceCode({
      clientId: 'client',
      userCode: 'FOOCODE',
      deviceInfo,
    }).save();

    await fixture3.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-CODE',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceConfirmForm" method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`));

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, sinon.match((client) => {
      assert.equal(client.clientId, 'client');
      return true;
    }), deviceInfo);
  });

  it('re-renders on no submitted code', { timeout: 3000 }, async () => {
    const errSpy = sinon.spy();
    fixture3.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeInputSource');

    await fixture3.agent.post(route)
      .send({ xsrf })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'NoCodeError');
      return true;
    }));

    ((actual) => { assert.ok('called' in Object(actual)); assert.equal(actual.called, false); })(errSpy);
  });

  it('re-renders on not found code', { timeout: 3000 }, async () => {
    const errSpy = sinon.spy();
    fixture3.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeInputSource');

    await fixture3.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-NOT-FOUND',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'NotFoundError');
      return true;
    }));

    ((actual) => { assert.ok('called' in Object(actual)); assert.equal(actual.called, false); })(errSpy);
  });

  it('re-renders on found but expired code', { timeout: 3000 }, async () => {
    const errSpy = sinon.spy();
    fixture3.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeInputSource');
    await new fixture3.provider.DeviceCode({
      userCode: 'FOOEXPIRED',
    }).save();

    timekeeper.travel(Date.now() + (((10 * 60) + 10) * 1000));
    await fixture3.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-EXPIRED',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'ExpiredError');
      return true;
    }));

    ((actual) => { assert.ok('called' in Object(actual)); assert.equal(actual.called, false); })(errSpy);
  });

  it('re-renders on found but already user code', { timeout: 3000 }, async () => {
    const errSpy = sinon.spy();
    fixture3.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeInputSource');
    await new fixture3.provider.DeviceCode({
      userCode: 'FOOCONSUMED',
      accountId: 'account',
    }).save();

    await fixture3.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-CONSUMED',
      })
      .type('form')
      .expect(200)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`))
      .expect(/<p class="red">The code you entered is incorrect\. Try again<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'AlreadyUsedError');
      return true;
    }));

    ((actual) => { assert.ok('called' in Object(actual)); assert.equal(actual.called, false); })(errSpy);
  });

  it('re-renders on invalid client', { timeout: 3000 }, async () => {
    const errSpy = sinon.spy();
    fixture3.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeInputSource');
    await new fixture3.provider.DeviceCode({
      userCode: 'FOONOTFOUNDCLIENT',
      clientId: 'client',
    }).save();

    sinon.stub(fixture3.provider.Client, 'find').callsFake(async () => { });
    await fixture3.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-NOT-FOUND-CLIENT',
      })
      .type('form')
      .expect(400)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`))
      .expect(/<p class="red">There was an error processing your request<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'InvalidClient');
      return true;
    }));

    assert.equal(errSpy.calledOnce, true);
  });

  it('re-renders on !ctx.oidc.session.state', { timeout: 3000 }, async () => {
    const errSpy = sinon.spy();
    fixture3.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeInputSource');
    await new fixture3.provider.DeviceCode({
      userCode: 'FOOCSRF1',
    }).save();

    delete fixture3.getSession().state;
    await fixture3.agent.post(route)
      .send({
        xsrf,
        user_code: 'FOO-CSRF-1',
      })
      .type('form')
      .expect(400)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`))
      .expect(/<p class="red">There was an error processing your request<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'InvalidRequest');
      assert.equal(err.error_description, 'could not find device form details');
      return true;
    }));

    assert.equal(errSpy.calledOnce, true);
  });

  it('re-renders on invalid csrf', { timeout: 3000 }, async () => {
    const errSpy = sinon.spy();
    fixture3.provider.once('code_verification.error', errSpy);
    const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'userCodeInputSource');
    await new fixture3.provider.DeviceCode({
      userCode: 'FOOCSRF2',
    }).save();

    await fixture3.agent.post(route)
      .send({
        xsrf: 'invalid-csrf',
        user_code: 'FOO-CSRF-FOO',
      })
      .type('form')
      .expect(400)
      .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture3.suitePath('/device')}">`))
      .expect(/<p class="red">There was an error processing your request<\/p>/);

    assert.equal(spy.calledOnce, true);
    sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
      assert.equal(err.name, 'InvalidRequest');
      assert.equal(err.error_description, 'xsrf token invalid');
      return true;
    }));

    assert.equal(errSpy.calledOnce, true);
  });
});

describe('POST code_verification endpoint w/ verification', () => {
  const fixture4 = {};

  before(bootstrap(import.meta.url, fixture4), { timeout: 3000 });
  before(() => fixture4.login({
      scope: 'openid email',
      rejectedClaims: ['email_verified'],
    }), { timeout: 3000 });
  afterEach(() => timekeeper.reset(), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  const xsrf = 'foo';

  beforeEach(() => {
    fixture4.getSession().state = { secret: xsrf };
  }, { timeout: 3000 });

  passInteractionChecks(fixture4, 'native_client_prompt', 'op_claims_missing', () => {
    const fixture5 = Object.create(fixture4);

    it('accepts an abort command', { timeout: 3000 }, async () => {
      const spy = sinon.spy(i(fixture5.provider).features.deviceFlow, 'userCodeInputSource');

      let code = await new fixture5.provider.DeviceCode({
        clientId: 'client',
        userCode: 'FOO',
        params: {
          scope: 'openid email',
          client_id: 'client',
          claims: JSON.stringify({ userinfo: { email: null } }),
        },
      }).save();

      await fixture5.agent.post(route)
        .send({
          xsrf,
          confirm: '',
          abort: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200)
        .expect(/The Sign-in request was interrupted/);

      code = await fixture5.provider.DeviceCode.find(code);

      assert.ok(!('accountId' in Object(code)));
      ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'access_denied'); })(code);
      ((actual) => { assert.ok('errorDescription' in Object(actual)); assert.equal(actual.errorDescription, 'End-User aborted interaction'); })(code);

      assert.equal(spy.calledOnce, true);
    });

    it('renders a confirmation and assigns', { timeout: 3000 }, async () => {
      const spy = sinon.spy(i(fixture5.provider).features.deviceFlow, 'successSource');

      let code = await new fixture5.provider.DeviceCode({
        clientId: 'client',
        userCode: 'FOO',
        params: {
          scope: 'openid email',
          client_id: 'client',
          claims: JSON.stringify({ userinfo: { email: null } }),
        },
      }).save();

      await fixture5.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200);

      code = await fixture5.provider.DeviceCode.find(code);

      const session = fixture5.getSession();

      assert.ok(!('sid' in Object(code)));
      ((actual) => { assert.ok('accountId' in Object(actual)); assert.equal(actual.accountId, session.accountId); })(code);
      ((actual) => { assert.ok('authTime' in Object(actual)); assert.equal(actual.authTime, session.loginTs); })(code);
      ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email'); })(code);
      ((actual) => { assert.ok('claims' in Object(actual)); assert.deepEqual(actual.claims, { userinfo: { email: null } }); })(code);

      assert.equal(spy.calledOnce, true);
    });

    it('renders a confirmation and assigns (incl. sid because of client configuration)', { timeout: 3000 }, async () => {
      const spy = sinon.spy(i(fixture5.provider).features.deviceFlow, 'successSource');

      let code = await new fixture5.provider.DeviceCode({
        clientId: 'client-backchannel',
        userCode: 'FOO',
        params: {
          scope: 'openid',
          client_id: 'client-backchannel',
        },
      }).save();

      await fixture5.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200);

      code = await fixture5.provider.DeviceCode.find(code);

      assert.ok('sid' in Object(code));
      assert.equal(spy.calledOnce, true);
    });

    it('renders a confirmation and assigns (incl. sid because of claims)', { timeout: 3000 }, async () => {
      const spy = sinon.spy(i(fixture5.provider).features.deviceFlow, 'successSource');

      let code = await new fixture5.provider.DeviceCode({
        clientId: 'client',
        userCode: 'FOO',
        params: {
          scope: 'openid',
          client_id: 'client',
          claims: JSON.stringify({ id_token: { sid: null } }),
        },
      }).save();

      await fixture5.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'FOO',
        })
        .type('form')
        .expect(200);

      code = await fixture5.provider.DeviceCode.find(code);

      assert.ok('sid' in Object(code));
      assert.equal(spy.calledOnce, true);
    });

    it('allows for punctuation to be included and characters to be downcased', { timeout: 3000 }, async () => {
      const spy = sinon.spy(i(fixture5.provider).features.deviceFlow, 'successSource');

      let code = await new fixture5.provider.DeviceCode({
        clientId: 'client',
        userCode: 'FOOBAR',
        params: {
          scope: 'openid email',
          client_id: 'client',
          claims: JSON.stringify({ userinfo: { email: null } }),
        },
      }).save();

      await fixture5.agent.post(route)
        .send({
          xsrf,
          confirm: 'yes',
          user_code: 'f o o b a r',
        })
        .type('form')
        .expect(200);

      code = await fixture5.provider.DeviceCode.find(code);

      const session = fixture5.getSession();

      ((actual) => { assert.ok('accountId' in Object(actual)); assert.equal(actual.accountId, session.accountId); })(code);
      ((actual) => { assert.ok('authTime' in Object(actual)); assert.equal(actual.authTime, session.loginTs); })(code);
      ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email'); })(code);
      ((actual) => { assert.ok('claims' in Object(actual)); assert.deepEqual(actual.claims, { userinfo: { email: null } }); })(code);

      assert.equal(spy.calledOnce, true);
    });
  });
});
