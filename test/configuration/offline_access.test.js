const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('Provider declaring support for refresh_token grant type', () => {
  it('is enabled by default', () => {
    const provider = new Provider('https://op.example.com');
    expect(i(provider).configuration().grantTypes).to.contain('refresh_token');
  });

  it('isnt enabled when offline_access isnt amongst the scopes', () => {
    const provider = new Provider('https://op.example.com', { scopes: ['openid'] });
    expect(i(provider).configuration().grantTypes).not.to.contain('refresh_token');
  });

  it('is enabled when offline_access isnt amongst the scopes', () => {
    const provider = new Provider('https://op.example.com', { scopes: ['openid', 'offline_access'] });
    expect(i(provider).configuration().grantTypes).to.contain('refresh_token');
  });

  it('is enabled when issueRefreshToken configuration function is configured', () => {
    const provider = new Provider('https://op.example.com', {
      scopes: ['openid'],
      issueRefreshToken() {
        return true;
      },
    });
    expect(i(provider).configuration().grantTypes).to.contain('refresh_token');
  });
});
