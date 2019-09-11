const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('pathFor related behaviors', () => {
  it('throws an Error when invalid route path is requested', () => {
    const provider = new Provider('http://localhost');
    expect(provider.pathFor('authorization')).to.equal('/auth');
    expect(() => provider.pathFor('foobar')).to.throw(Error, 'No route found for name: foobar');
  });

  it('interactionUrl resolves to /interaction/uid when devInteractions is disabled', async () => {
    const provider = new Provider('http://localhost', {
      features: {
        devInteractions: { enabled: false },
      },
    });

    const url = await i(provider).configuration('interactions.url')({
      oidc: {
        uid: 'foobar',
      },
    });

    expect(url).to.equal('/interaction/foobar');
  });
});
