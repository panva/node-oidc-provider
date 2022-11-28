const { expect } = require('chai');

const bootstrap = require('../test_helper.js');

describe('Client#add', () => {
  before(bootstrap(__dirname, { config: 'client_secrets' }));

  it('client secret is mandatory if client auth needs it', function () {
    expect(this.provider.Client.needsSecret({
      token_endpoint_auth_method: 'client_secret_basic',
    })).to.be.true;
  });
});
