const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('Client#add', () => {
  before(bootstrap(__dirname, { config: 'client_secrets' }));

  it('client secret is mandatory if even one of the authz needs it', function () {
    expect(this.provider.Client.needsSecret({
      token_endpoint_auth_method: 'none',
      revocation_endpoint_auth_method: 'none',
      introspection_endpoint_auth_method: 'client_secret_basic',
    })).to.be.true;
    expect(this.provider.Client.needsSecret({
      token_endpoint_auth_method: 'none',
      revocation_endpoint_auth_method: 'client_secret_basic',
      introspection_endpoint_auth_method: 'none',
    })).to.be.true;
    expect(this.provider.Client.needsSecret({
      token_endpoint_auth_method: 'client_secret_basic',
      revocation_endpoint_auth_method: 'none',
      introspection_endpoint_auth_method: 'none',
    })).to.be.true;
  });
});
