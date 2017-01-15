'use strict';

require('../test_helper');
const Provider = require('../../lib');
const { expect } = require('chai');

describe('pathFor related behaviors', function () {
  it('throws an Error when invalid route path is requested', function () {
    return new Provider('http://localhost').initialize().then((provider) => {
      expect(provider.pathFor('authorization')).to.equal('/auth');
      expect(() => provider.pathFor('foobar')).to.throw(Error, 'No route found for name: foobar');
    });
  });

  it('interactionUrl resolves to /interaction/uuid when devInteractions is disabled', function () {
    const provider = new Provider('http://localhost', {
      features: {
        devInteractions: false,
      },
    });

    expect(i(provider).configuration('interactionUrl').call({
      oidc: {
        uuid: 'foobar',
      }
    })).to.equal('/interaction/foobar');
  });
});
