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
