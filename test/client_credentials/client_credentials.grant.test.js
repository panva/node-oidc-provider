'use strict';

const {
  agent, provider
} = require('../test_helper')(__dirname);
const sinon = require('sinon');
const { stringify: qs } = require('querystring');
const { expect } = require('chai');

const route = '/token';

provider.setupClient();
provider.setupCerts();

describe('grant_type=client_credentials', function () {
  it('provides a Bearer client credentials token', function () {
    const spy = sinon.spy();
    provider.once('grant.success', spy);

    return agent.post(route)
    .auth('client', 'secret')
    .send(qs({
      grant_type: 'client_credentials'
    }))
    .expect(200)
    .expect(function () {
      expect(spy.calledOnce).to.be.true;
    })
    .expect(function (response) {
      expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type');
    });
  });
});
