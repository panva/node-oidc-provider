import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('configuration features.encryption', () => {
  before(bootstrap(import.meta.url));

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
          'userinfo_encryption_enc_values_supported',
          'introspection_encryption_alg_values_supported',
          'introspection_encryption_enc_values_supported',
        );
      });
  });
});
