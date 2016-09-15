'use strict';

const { expect } = require('chai');
const sinon = require('sinon');
const bootstrap = require('../test_helper');

describe('custom response modes', () => {
  const { provider, agent, AuthorizationRequest } = bootstrap(__dirname);

  provider.setupClient();
  before(agent.login);

  it('allows for grant types to be added', () => {
    expect(() => {
      provider.registerResponseMode('custom', function handler() {});
    }).not.to.throw();
  });

  it('is used for success authorization results', function () {
    const spy = sinon.spy();
    provider.registerResponseMode('custom', spy);

    const auth = new AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom'
    });

    return agent.get('/auth')
      .query(auth)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.calledWith('https://client.example.com/cb')).to.be.true;
        expect(spy.firstCall.args[1]).to.have.keys('code', 'state');
      });
  });

  it('is used for error authorization results', function () {
    const spy = sinon.spy();
    provider.registerResponseMode('custom', spy);

    const auth = new AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom',
      prompt: 'none login' // causes invalid_request
    });

    return agent.get('/auth')
      .query(auth)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.calledWith('https://client.example.com/cb')).to.be.true;
        expect(spy.firstCall.args[1]).to.have.keys('error', 'error_description', 'state');
      });
  });
});
