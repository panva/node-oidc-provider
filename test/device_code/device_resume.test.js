import { describe, before, beforeEach, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';

import nanoid from '../../lib/helpers/nanoid.js';
import bootstrap, { passInteractionChecks } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import { generate } from '../../lib/helpers/user_codes.js';

const sinon = createSandbox();
const { any } = sinon.match;

const expire = new Date();
expire.setDate(expire.getDate() + 1);

let uid;
let userCode;
let path;

describe('device interaction resume /device/:uid/', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  beforeEach(() => {
    uid = nanoid();
    userCode = generate('base-20', '***-***-***');
    path = fixture.suitePath(`/device/${uid}`);
  }, { timeout: 3000 });

  afterEach(() => sinon.restore(), { timeout: 3000 });

  async function setup(auth, result, sessionData) {
    assert.ok(auth);

    const cookies = [];

    const params = {
      client_id: 'client',
      ...auth,
    };

    const session = new this.provider.Session({ jti: 'sess', ...sessionData });
    const deviceCode = await new this.provider.DeviceCode({
      params,
      clientId: 'client',
      userCode,
    }).save();

    const interaction = new this.provider.Interaction(uid, { uid, session, deviceCode });

    const cookie = `_interaction_resume=${uid}; path=${path}; expires=${expire.toGMTString()}; httponly`;
    cookies.push(cookie);
    Object.assign(interaction, { params });

    const sessionCookie = `_session=sess; path=/; expires=${expire.toGMTString()}; httponly`;
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

  passInteractionChecks(fixture, 'native_client_prompt', () => {
    const fixture1 = Object.create(fixture);

    describe('general', () => {
      const fixture2 = Object.create(fixture1);

      it('needs the resume cookie to be present, else renders an err', { timeout: 3000 }, async () => {
        const spy = sinon.spy(i(fixture2.provider).features.deviceFlow, 'userCodeInputSource');

        await setup.call(fixture2, {
          scope: 'openid',
        }, {
          login: {
            accountId: nanoid(),
            remember: true,
          },
          consent: {},
        });

        fixture2.agent._saveCookies.bind(fixture2.agent)({
          request: { url: fixture2.provider.issuer },
          headers: { 'set-cookie': `_interaction_resume=; path=${path}; httpOnly` },
        });

        await fixture2.agent.get(path)
          .accept('text/html')
          .expect(400)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture2.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        assert.equal(spy.calledOnce, true);
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          assert.equal(err.name, 'SessionNotFound');
          assert.equal(err.error_description, 'authorization request has expired');
          return true;
        }));
      });

      it('needs to find the session to resume', { timeout: 3000 }, async () => {
        const spy = sinon.spy(i(fixture2.provider).features.deviceFlow, 'userCodeInputSource');

        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(fixture2, auth);

        sinon.stub(fixture2.provider.Interaction, 'find').resolves();

        await fixture2.agent.get(path)
          .accept('text/html')
          .expect(400)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture2.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        assert.equal(spy.calledOnce, true);
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          assert.equal(err.name, 'SessionNotFound');
          assert.equal(err.error_description, 'interaction session not found');
          return true;
        }));
      });

      it('needs to find the code to resume', { timeout: 3000 }, async () => {
        const spy = sinon.spy(i(fixture2.provider).features.deviceFlow, 'userCodeInputSource');

        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(fixture2, auth);

        sinon.stub(fixture2.provider.DeviceCode, 'find').resolves();

        await fixture2.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture2.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        assert.equal(spy.calledOnce, true);
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          assert.equal(err.name, 'NotFoundError');
          assert.equal(err.message, 'the code was not found');
          return true;
        }));
      });

      it('checks code is not expired', { timeout: 3000 }, async () => {
        const spy = sinon.spy(i(fixture2.provider).features.deviceFlow, 'userCodeInputSource');

        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(fixture2, auth);

        sinon.stub(fixture2.provider.DeviceCode, 'find').resolves({ isExpired: true });

        await fixture2.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture2.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        assert.equal(spy.calledOnce, true);
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          assert.equal(err.name, 'ExpiredError');
          assert.equal(err.message, 'the code has expired');
          return true;
        }));
      });

      it('checks code is not used already (1/2)', { timeout: 3000 }, async () => {
        const spy = sinon.spy(i(fixture2.provider).features.deviceFlow, 'userCodeInputSource');

        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(fixture2, auth);

        sinon.stub(fixture2.provider.DeviceCode, 'find').resolves({ accountId: 'foo' });

        await fixture2.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture2.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        assert.equal(spy.calledOnce, true);
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          assert.equal(err.name, 'AlreadyUsedError');
          assert.equal(err.message, 'code has already been used');
          return true;
        }));
      });

      it('checks code is not used already (2/2)', { timeout: 3000 }, async () => {
        const spy = sinon.spy(i(fixture2.provider).features.deviceFlow, 'userCodeInputSource');

        const auth = new fixture2.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        await setup.call(fixture2, auth);

        sinon.stub(fixture2.provider.DeviceCode, 'find').resolves({ error: 'access_denied' });

        await fixture2.agent.get(path)
          .accept('text/html')
          .expect(200)
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture2.suitePath('/device')}">`))
          .expect(/<p class="red">There was an error processing your request<\/p>/);

        assert.equal(spy.calledOnce, true);
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          assert.equal(err.name, 'AlreadyUsedError');
          assert.equal(err.message, 'code has already been used');
          return true;
        }));
      });
    });

    describe('login results', () => {
      const fixture3 = Object.create(fixture1);

      it('should process newly established permanent sessions (default)', { timeout: 3000 }, async () => {
        sinon.stub(fixture3.provider.Grant.prototype, 'getOIDCScope').returns('openid');
        const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'successSource');

        await setup.call(fixture3, {
          scope: 'openid',
        }, {
          login: {
            accountId: nanoid(),
          },
          consent: {},
        });

        await fixture3.agent.get(path)
          .accept('text/html')
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(200)
          .expect('set-cookie', /expires/) // expect a permanent cookie
          .expect(() => {
            ((actual) => { assert.ok(actual); assert.ok(!('transient' in Object(actual))); })(fixture3.getSession());
          });

        const code = await fixture3.provider.DeviceCode.findByUserCode(userCode);
        assert.ok('accountId' in Object(code));
      });

      it('should process newly established permanent sessions (explicit)', { timeout: 3000 }, async () => {
        sinon.stub(fixture3.provider.Grant.prototype, 'getOIDCScope').returns('openid');
        const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'successSource');

        await setup.call(fixture3, {
          scope: 'openid',
        }, {
          login: {
            accountId: nanoid(),
            remember: true,
          },
          consent: {},
        });

        await fixture3.agent.get(path)
          .accept('text/html')
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(200)
          .expect('set-cookie', /expires/) // expect a permanent cookie
          .expect(() => {
            ((actual) => { assert.ok(actual); assert.ok(!('transient' in Object(actual))); })(fixture3.getSession());
          });

        const code = await fixture3.provider.DeviceCode.findByUserCode(userCode);
        assert.ok('accountId' in Object(code));
      });

      it('should process newly established temporary sessions', { timeout: 3000 }, async () => {
        sinon.stub(fixture3.provider.Grant.prototype, 'getOIDCScope').returns('openid');
        const spy = sinon.spy(i(fixture3.provider).features.deviceFlow, 'successSource');

        await setup.call(fixture3, {
          scope: 'openid',
        }, {
          login: {
            accountId: nanoid(),
            remember: false,
          },
          consent: {},
        });

        await fixture3.agent.get(path)
          .accept('text/html')
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect(200)
          .expect(() => {
            ((actual) => { assert.ok(actual); assert.ok('transient' in Object(actual)); })(fixture3.getSession());
          });

        const code = await fixture3.provider.DeviceCode.findByUserCode(userCode);
        assert.ok('accountId' in Object(code));
      });

      it('should trigger logout when the session subject changes', { timeout: 3000 }, async () => {
        sinon.stub(fixture3.provider.Grant.prototype, 'getOIDCScope').returns('openid');
        const auth = new fixture3.AuthorizationRequest({
          scope: 'openid',
        });

        await setup.call(fixture3, auth, {
          login: {
            accountId: nanoid(),
          },
        }, {
          accountId: nanoid(),
        });

        let state;

        await fixture3.agent.get(path)
          .expect(200)
          .expect('content-type', 'text/html; charset=utf-8')
          .expect(/document.addEventListener\('DOMContentLoaded', function \(\) { document.forms\[0\].submit\(\) }\);/)
          .expect(/<input type="hidden" name="logout" value="yes"\/>/)
          .expect(({ text }) => {
            ({ state } = fixture3.getSession());
            ((actual) => { assert.ok('clientId' in Object(actual)); assert.equal(actual.clientId, 'client'); })(state);
            ((actual) => { assert.ok('postLogoutRedirectUri' in Object(actual)); assert.match(actual.postLogoutRedirectUri, new RegExp(`${path}$`)); })(state);
            assert.match(text, new RegExp(`input type="hidden" name="xsrf" value="${state.secret}"`));
          })
          .expect(/<form method="post" action=".+\/session\/end\/confirm">/);

        assert.ok(await fixture3.provider.Interaction.find(uid));

        await fixture3.agent.post('/session/end/confirm')
          .send({
            xsrf: state.secret,
            logout: 'yes',
          })
          .type('form')
          .expect(303)
          .expect('location', state.postLogoutRedirectUri);

        await fixture3.agent.get(state.postLogoutRedirectUri.replace(fixture3.provider.issuer, ''))
          .expect(200);
      });
    });

    describe('interaction errors', () => {
      const fixture4 = Object.create(fixture1);

      it('should abort an interaction when given an error result object', { timeout: 3000 }, async () => {
        const spy = sinon.spy(i(fixture4.provider).features.deviceFlow, 'userCodeInputSource');

        await setup.call(fixture4, {
          scope: 'openid',
        }, {
          error: 'access_denied',
          error_description: 'scope out of reach',
        });

        await fixture4.agent.get(path)
          .accept('text/html')
          .expect(new RegExp(`<form id="op.deviceInputForm" novalidate method="post" action="http://127.0.0.1:\\d+${fixture4.suitePath('/device')}">`))
          .expect(/<p class="red">The Sign-in request was interrupted<\/p>/);

        assert.equal(spy.calledOnce, true);
        sinon.assert.calledWithMatch(spy, any, any, any, sinon.match((err) => {
          assert.equal(err.message, 'the interaction was aborted');
          ((actual) => { assert.ok(actual instanceof Error); assert.ok('error' in Object(actual)); assert.equal(actual.error, 'access_denied'); })(err.cause);
          return true;
        }));
      });
    });
  });
});
