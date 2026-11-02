import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';

import bootstrap from '../test_helper.js';

describe('configuration features.encryption', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  it('extends discovery', { timeout: 3000 }, () => fixture.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        assert.ok(['id_token_encryption_alg_values_supported', 'id_token_encryption_enc_values_supported', 'request_object_encryption_alg_values_supported', 'request_object_encryption_enc_values_supported', 'userinfo_encryption_alg_values_supported', 'userinfo_encryption_enc_values_supported', 'introspection_encryption_alg_values_supported', 'introspection_encryption_enc_values_supported'].every((key) => Object.keys(response.body).includes(key)));
      }));
});
