import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

describe('custom response modes', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  before(() => fixture.login(), { timeout: 3000 });

  it('allows for grant types to be added', { timeout: 3000 }, () => {
    assert.doesNotThrow(() => {
      fixture.provider.registerResponseMode('custom', () => {});
    });
  });

  it('is used for success authorization results', { timeout: 3000 }, () => {
    const spy = sinon.spy();
    fixture.provider.registerResponseMode('custom2', spy);

    const auth = new fixture.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom2',
    });

    return fixture.agent.get('/auth')
      .query(auth)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
        assert.equal(spy.firstCall.args[1], 'https://client.example.com/cb');
        assert.deepEqual(new Set(Object.keys(spy.firstCall.args[2])), new Set(['code', 'state', 'iss']));
      });
  });

  it('is used for error authorization results', { timeout: 3000 }, () => {
    const spy = sinon.spy();
    fixture.provider.registerResponseMode('custom3', spy);

    const auth = new fixture.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom3',
      prompt: 'none login', // causes invalid_request
    });

    return fixture.agent.get('/auth')
      .query(auth)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
        assert.equal(spy.firstCall.args[1], 'https://client.example.com/cb');
        assert.deepEqual(new Set(Object.keys(spy.firstCall.args[2])), new Set(['error', 'error_description', 'state', 'iss']));
      });
  });

  it('handles invalid response_mode values', { timeout: 3000 }, () => {
    const auth = new fixture.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'foo',
    });

    return fixture.agent.get('/auth')
      .query(auth)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('unsupported_response_mode'))
      .expect(auth.validateErrorDescription('unsupported response_mode requested'));
  });
});
