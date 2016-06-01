'use strict';

const {
  provider, agent
} = require('../test_helper')(__dirname);
const { expect } = require('chai');

provider.setupCerts();

describe('configuration features.encryption', function () {
  it('extends discovery', function () {
    return agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect(function (response) {
        expect(response.body).to.contain.keys(
          'check_session_iframe',
          'end_session_endpoint'
        );
      });
  });
});
