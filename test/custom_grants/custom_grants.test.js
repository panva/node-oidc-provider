'use strict';

const { expect } = require('chai');
const bootstrap = require('../test_helper');

describe('custom token endpoint grant types', function () {
  before(bootstrap(__dirname)); // provider, agent

  it('allows for grant types to be added', function () {
    expect(() => {
      this.provider.registerGrantType('lotto', (passedProvider) => {
        expect(passedProvider).to.equal(this.provider);
        return function* (next) {
          this.body = { winner: this.oidc.params.name };
          this.status = 201;
          yield next;
        };
      }, ['name']);
    }).not.to.throw();

    expect(i(this.provider).configuration('grantTypes').has('lotto')).to.be.true;
  });

  it('does not need to be passed extra parameters', function () {
    expect(() => {
      this.provider.registerGrantType('lotto-2', () => function* () {}); // eslint-disable-line no-empty-function
    }).not.to.throw();

    expect(i(this.provider).configuration('grantTypes').has('lotto-2')).to.be.true;
  });

  it('can be passed null or a string', function () {
    expect(() => {
      this.provider.registerGrantType('lotto-3', () => function* () {}, null); // eslint-disable-line no-empty-function
      this.provider.registerGrantType('lotto-4', () => function* () {}, 'name'); // eslint-disable-line no-empty-function
    }).not.to.throw();

    expect(i(this.provider).configuration('grantTypes').has('lotto-3')).to.be.true;
    expect(i(this.provider).configuration('grantTypes').has('lotto-4')).to.be.true;
  });

  describe('when added', function () {
    before(function* () {
      const client = yield this.provider.Client.find('client');
      client.grantTypes.push('lotto');
    });

    it('clients can start using it', function () {
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'lotto', name: 'Filip' })
        .type('form')
        .expect(201)
        .expect({ winner: 'Filip' });
    });
  });
});
