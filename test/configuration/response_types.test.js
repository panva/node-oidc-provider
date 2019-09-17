const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('response_types Provider configuration', () => {
  it('fixes common issues', () => {
    const provider = new Provider('https://op.example.com', { // eslint-disable-line no-new
      responseTypes: ['token id_token code', 'token id_token'],
    });
    expect(i(provider).configuration('responseTypes')).to.eql(['code id_token token', 'id_token token']);
  });

  it('throws when invalid types are configured', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        responseTypes: ['id_token tokencode'],
      });
    }).to.throw('unsupported response type: id_token tokencode');
  });

  it('validates none is always standalone', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        responseTypes: ['none code'],
      });
    }).to.throw('unsupported response type: none code');
  });
});
