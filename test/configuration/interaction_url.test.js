require('../test_helper');
const Provider = require('../../lib');
const { expect } = require('chai');

describe('pathFor related behaviors', () => {
  it('throws an Error when invalid route path is requested', () => new Provider('http://localhost').initialize().then((provider) => {
    expect(provider.pathFor('authorization')).to.equal('/auth');
    expect(() => provider.pathFor('foobar')).to.throw(Error, 'No route found for name: foobar');
  }));

  it('interactionUrl resolves to /interaction/uuid when devInteractions is disabled', async () => {
    const provider = new Provider('http://localhost', {
      features: {
        devInteractions: false,
      },
    });

    const interactionUrl = await i(provider).configuration('interactionUrl')({
      oidc: {
        uuid: 'foobar',
      },
    });

    expect(interactionUrl).to.equal('/interaction/foobar');
  });
});
