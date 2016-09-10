'use strict';

const { expect } = require('chai');
const bootstrap = require('../test_helper');

describe('custom token endpoint grant types', () => {
  const { provider, agent } = bootstrap(__dirname);

  it('allows for grant types to be added', () => {
    expect(() => {
      provider.registerGrantType('lotto', (passedProvider) => {
        expect(passedProvider).to.equal(provider);
        return function* (next) {
          this.body = { winner: this.oidc.params.name };
          this.status = 201;
          yield next;
        };
      }, ['name']);
    }).not.to.throw();

    expect(provider.configuration('grantTypes').has('lotto')).to.be.true;
  });

  it('does not need to be passed extra parameters', () => {
    expect(() => {
      provider.registerGrantType('lotto-2', () => function* () {}); // eslint-disable-line no-empty-function
    }).not.to.throw();

    expect(provider.configuration('grantTypes').has('lotto-2')).to.be.true;
  });

  it('can be passed null or a string', () => {
    expect(() => {
      provider.registerGrantType('lotto-3', () => function* () {}, null); // eslint-disable-line no-empty-function
      provider.registerGrantType('lotto-4', () => function* () {}, 'name'); // eslint-disable-line no-empty-function
    }).not.to.throw();

    expect(provider.configuration('grantTypes').has('lotto-3')).to.be.true;
    expect(provider.configuration('grantTypes').has('lotto-4')).to.be.true;
  });

  describe('when added', () => {
    provider.setupClient();

    it('clients can start using it', () => {
      return agent.post('/token')
      .auth('client', 'secret')
      .send({ grant_type: 'lotto', name: 'Filip' })
      .type('form')
      .expect(201)
      .expect({ winner: 'Filip' });
    });
  });
});
