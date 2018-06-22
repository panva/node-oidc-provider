const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('configuration features.encryption', () => {
  before(bootstrap(__dirname));

  it('extends discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.contain.keys(
          'check_session_iframe',
          'end_session_endpoint',
        );
      });
  });
});
