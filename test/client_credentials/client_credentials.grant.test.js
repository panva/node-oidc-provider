'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/token';

describe('grant_type=client_credentials', () => {
  const { agent, provider } = bootstrap(__dirname);
  provider.setupClient();

  it('provides a Bearer client credentials token', () => {
    const spy = sinon.spy();
    provider.once('grant.success', spy);

    return agent.post(route)
    .auth('client', 'secret')
    .send({
      grant_type: 'client_credentials'
    })
    .type('form')
    .expect(200)
    .expect(() => {
      expect(spy.calledOnce).to.be.true;
    })
    .expect((response) => {
      expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type');
    });
  });
});
