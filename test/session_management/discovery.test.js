'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');

describe('configuration features.encryption', function () {
  before(bootstrap(__dirname)); // agent

  it('extends discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.contain.keys(
          'check_session_iframe',
          'end_session_endpoint'
        );
      });
  });
});
