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
          'id_token_encryption_alg_values_supported',
          'id_token_encryption_enc_values_supported',
          'request_object_encryption_alg_values_supported',
          'request_object_encryption_enc_values_supported',
          'userinfo_encryption_alg_values_supported',
          'userinfo_encryption_enc_values_supported'
        );
      });
  });
});
