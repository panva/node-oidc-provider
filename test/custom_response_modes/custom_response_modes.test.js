'use strict';

const { expect } = require('chai');
const sinon = require('sinon');
const bootstrap = require('../test_helper');

describe('custom response modes', function () {
  before(bootstrap(__dirname)); // provider, agent, AuthorizationRequest

  before(function () { return this.login(); });

  it('allows for grant types to be added', function () {
    expect(() => {
      this.provider.registerResponseMode('custom', function handler() {});
    }).not.to.throw();
  });

  it('is used for success authorization results', function () {
    const spy = sinon.spy();
    this.provider.registerResponseMode('custom', spy);

    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom'
    });

    return this.agent.get('/auth')
      .query(auth)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.calledWith('https://client.example.com/cb')).to.be.true;
        expect(spy.firstCall.args[1]).to.have.keys('code', 'state');
      });
  });

  it('is used for error authorization results', function () {
    const spy = sinon.spy();
    this.provider.registerResponseMode('custom', spy);

    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom',
      prompt: 'none login' // causes invalid_request
    });

    return this.agent.get('/auth')
      .query(auth)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.calledWith('https://client.example.com/cb')).to.be.true;
        expect(spy.firstCall.args[1]).to.have.keys('error', 'error_description', 'state');
      });
  });
});
