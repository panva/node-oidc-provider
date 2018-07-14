const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('configuration features.deviceCode', () => {
  before(bootstrap(__dirname)); // agent

  it('extends discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.contain.keys('device_authorization_endpoint');
      });
  });
});
