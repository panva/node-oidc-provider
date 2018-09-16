const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

describe('custom response modes', () => {
  before(bootstrap(__dirname));

  before(function () { return this.login(); });

  it('allows for grant types to be added', function () {
    expect(() => {
      this.provider.registerResponseMode('custom', () => {});
    }).not.to.throw();
  });

  it('is used for success authorization results', function () {
    const spy = sinon.spy();
    this.provider.registerResponseMode('custom2', spy);

    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom2',
    });

    return this.agent.get('/auth')
      .query(auth)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.firstCall.args[1]).to.equal('https://client.example.com/cb');
        expect(spy.firstCall.args[2]).to.have.keys('code', 'state');
      });
  });

  it('is used for error authorization results', function () {
    const spy = sinon.spy();
    this.provider.registerResponseMode('custom3', spy);

    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'custom3',
      prompt: 'none login', // causes invalid_request
    });

    return this.agent.get('/auth')
      .query(auth)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.firstCall.args[1]).to.equal('https://client.example.com/cb');
        expect(spy.firstCall.args[2]).to.have.keys('error', 'error_description', 'state');
      });
  });

  it('handles invalid response_mode values', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      response_mode: 'foo',
    });

    return this.agent.get('/auth')
      .query(auth)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('unsupported_response_mode'))
      .expect(auth.validateErrorDescription('unsupported response_mode requested'));
  });
});
