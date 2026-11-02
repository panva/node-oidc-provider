import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Configuration from '../../lib/helpers/configuration.js';

describe('Provider configuration', () => {
  it('rejects inherited enabled feature members', { timeout: 3000 }, () => {
    class DeviceFlow {}
    Object.defineProperties(DeviceFlow.prototype, {
      charset: { value: 'digits' },
      enabled: {
        get() {
          throw new Error('inherited getter was invoked');
        },
      },
      mask: { value: '***' },
    });

    assert.throws(() => new Configuration({
      features: { deviceFlow: new DeviceFlow() },
    }), (error) => { assert.ok(error.message.includes('features.deviceFlow.enabled must be an own property')); return true; });

    class DisabledDeviceFlow {}
    DisabledDeviceFlow.prototype.enabled = false;
    assert.throws(() => new Configuration({
      features: { deviceFlow: new DisabledDeviceFlow() },
    }), (error) => { assert.ok(error.message.includes('features.deviceFlow.enabled must be an own property')); return true; });
  });

  it('uses curated errors for null validation containers', { timeout: 3000 }, () => {
    assert.throws(() => new Configuration({ enabledJWA: null }), (error) => { assert.ok(error.message.includes('enabledJWA must be an object')); return true; });

    assert.throws(() => new Configuration({
      features: {
        openid4vci: {
          ack: 'experimental-01',
          credentialConfigurationsSupported: {
            example: {
              format: 'example',
              proof_types_supported: { attestation: null },
            },
          },
          enabled: true,
        },
      },
    }), (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['example'].proof_types_supported.attestation must be an object")); return true; });

    class ProofTypeConfiguration {}
    ProofTypeConfiguration.prototype.key_attestations_required = { key_storage: [] };
    assert.throws(() => new Configuration({
      features: {
        openid4vci: {
          ack: 'experimental-01',
          credentialConfigurationsSupported: {
            example: {
              format: 'example',
              proof_types_supported: {
                attestation: new ProofTypeConfiguration(),
              },
            },
          },
          enabled: true,
        },
      },
    }), (error) => { assert.ok(error.message.includes("features.openid4vci.credentialConfigurationsSupported['example'].proof_types_supported.attestation.key_attestations_required.key_storage must be a non-empty array of non-empty strings")); return true; });
  });

  it('does not mutate frozen configuration input', { timeout: 3000 }, () => {
    const input = {
      claims: {
        profile: ['name'],
      },
      clientAuthMethods: ['private_key_jwt'],
      enabledJWA: {
        clientAuthSigningAlgValues: ['HS256', 'RS256'],
      },
      extraParams: ['example'],
      features: {
        ciba: {
          deliveryModes: ['poll'],
        },
      },
      scopes: ['openid'],
      subjectTypes: ['public'],
    };

    Object.freeze(input.claims.profile);
    Object.freeze(input.claims);
    Object.freeze(input.clientAuthMethods);
    Object.freeze(input.enabledJWA.clientAuthSigningAlgValues);
    Object.freeze(input.enabledJWA);
    Object.freeze(input.extraParams);
    Object.freeze(input.features.ciba.deliveryModes);
    Object.freeze(input.features.ciba);
    Object.freeze(input.features);
    Object.freeze(input.scopes);
    Object.freeze(input.subjectTypes);
    Object.freeze(input);

    const configuration = new Configuration(input);

    assert.deepEqual(configuration.claims.profile, { name: null });
    assert.deepEqual(configuration.clientAuthSigningAlgValues, ['RS256']);
    assert.deepEqual(configuration.scopes, new Set(['openid', 'profile']));
    assert.deepEqual(input.claims.profile, ['name']);
    assert.deepEqual(input.enabledJWA.clientAuthSigningAlgValues, ['HS256', 'RS256']);
    assert.deepEqual(input.scopes, ['openid']);
  });

  it('copies Set configuration input before normalization', { timeout: 3000 }, () => {
    const input = {
      acrValues: new Set(['urn:example:acr']),
      claims: {
        profile: ['name'],
      },
      clientAuthMethods: new Set(['private_key_jwt']),
      extraParams: new Set(['example']),
      features: {
        ciba: {
          deliveryModes: new Set(['poll']),
        },
      },
      scopes: new Set(['openid']),
      subjectTypes: new Set(['public']),
    };

    const configuration = new Configuration(input);

    assert.notEqual(configuration.acrValues, input.acrValues);
    assert.notEqual(configuration.clientAuthMethods, input.clientAuthMethods);
    assert.notEqual(configuration.extraParams, input.extraParams);
    assert.notEqual(configuration.features.ciba.deliveryModes, input.features.ciba.deliveryModes);
    assert.notEqual(configuration.scopes, input.scopes);
    assert.notEqual(configuration.subjectTypes, input.subjectTypes);
    assert.deepEqual(input.scopes, new Set(['openid']));
    assert.deepEqual(configuration.scopes, new Set(['openid', 'profile']));
  });

  it('checks that a feature configuration property is valid', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Configuration({
        features: {
          foo: {},
        },
      });
    }, (error) => { assert.ok(error.message.includes('Unknown feature configuration: foo')); return true; });
  });

  it('can validate feature configuration after construction', { timeout: 3000 }, () => {
    const configuration = new Configuration();
    configuration.features.unknown = {};

    assert.throws(() => configuration.logDraftNotice(), (error) => { assert.ok(error.message.includes('Unknown feature configuration: unknown')); return true; });
  });

  it('checks that a stable feature does not have an ack', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Configuration({
        features: {
          deviceFlow: {
            enabled: true,
            ack: 'draft-01',
          },
        },
      });
    }, (error) => { assert.ok(error.message.includes("deviceFlow feature is now stable, the ack draft-01 is no longer valid. Check the stable feature's configuration for any breaking changes.")); return true; });
  });

  it('accepts stable and acknowledged experimental features together', { timeout: 3000 }, () => {
    assert.doesNotThrow(() => {
      new Configuration({
        features: {
          deviceFlow: {
            enabled: true,
          },
          webMessageResponseMode: {
            enabled: true,
            ack: 'individual-draft-01',
          },
        },
      });
    });
  });

  it('checks that a feature configuration is not a boolean', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Configuration({
        features: {
          devInteractions: false,
        },
      });
    }, (error) => { assert.ok(error.message.includes('Features are not enabled/disabled with a boolean value. See the documentation for more details.')); return true; });
    assert.throws(() => {
      new Configuration({
        features: {
          devInteractions: true,
        },
      });
    }, (error) => { assert.ok(error.message.includes('Features are not enabled/disabled with a boolean value. See the documentation for more details.')); return true; });
  });

  it('checks that cookies.long.sameSite is none when configuring enableHttpPostMethods', { timeout: 3000 }, () => {
    assert.equal(new Configuration().enableHttpPostMethods, false);
    assert.equal(new Configuration({ enableHttpPostMethods: false }).enableHttpPostMethods, false);
    assert.equal(new Configuration({
      enableHttpPostMethods: true,
      cookies: {
        long: {
          sameSite: 'none',
        },
      },
    }).enableHttpPostMethods, true);
    new Configuration({
      enableHttpPostMethods: true,
      cookies: {
        long: {
          sameSite: 'None',
        },
      },
    });
    new Configuration({
      enableHttpPostMethods: false,
      cookies: {
        long: {
          sameSite: 'Lax',
        },
      },
    });
    assert.throws(() => {
      new Configuration({
        enableHttpPostMethods: true,
      });
    }, (error) => { assert.ok(error.message.includes('HTTP POST Method support requires that cookies.long.sameSite is set to none')); return true; });
    assert.throws(() => {
      new Configuration({
        enableHttpPostMethods: true,
        cookies: {
          long: {
            sameSite: 'Lax',
          },
        },
      });
    }, (error) => { assert.ok(error.message.includes('HTTP POST Method support requires that cookies.long.sameSite is set to none')); return true; });
  });

  describe('fetchResponseBodyLimits', () => {
    it('accepts valid finite limits', { timeout: 3000 }, () => {
      const conf = new Configuration({
        fetchResponseBodyLimits: {
          'client_id metadata document': 1024,
          jwks_uri: 10240,
          sector_identifier_uri: 2048,
        },
      });
      assert.equal(conf.fetchResponseBodyLimits.jwks_uri, 10240);
    });

    it('accepts Infinity (no limit)', { timeout: 3000 }, () => {
      const conf = new Configuration({
        fetchResponseBodyLimits: {
          jwks_uri: Infinity,
        },
      });
      assert.equal(conf.fetchResponseBodyLimits.jwks_uri, Infinity);
    });

    it('rejects negative values', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: -1,
          },
        });
      }, (error) => { assert.ok(error.message.includes('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity')); return true; });
    });

    it('rejects non-number values', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: '1024',
          },
        });
      }, (error) => { assert.ok(error.message.includes('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity')); return true; });
    });

    it('rejects null values', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: null,
          },
        });
      }, (error) => { assert.ok(error.message.includes('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity')); return true; });
    });

    it('rejects NaN', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: NaN,
          },
        });
      }, (error) => { assert.ok(error.message.includes('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity')); return true; });
    });

    it('rejects floats', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: 10.5,
          },
        });
      }, (error) => { assert.ok(error.message.includes('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity')); return true; });
    });
  });
});
