import { expect } from 'chai';

import Configuration from '../../lib/helpers/configuration.js';

describe('Provider configuration', () => {
  it('rejects inherited enabled feature members', () => {
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

    expect(() => new Configuration({
      features: { deviceFlow: new DeviceFlow() },
    })).to.throw('features.deviceFlow.enabled must be an own property');

    class DisabledDeviceFlow {}
    DisabledDeviceFlow.prototype.enabled = false;
    expect(() => new Configuration({
      features: { deviceFlow: new DisabledDeviceFlow() },
    })).to.throw('features.deviceFlow.enabled must be an own property');
  });

  it('uses curated errors for null validation containers', () => {
    expect(() => new Configuration({ enabledJWA: null }))
      .to.throw('enabledJWA must be an object');

    expect(() => new Configuration({
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
    })).to.throw("features.openid4vci.credentialConfigurationsSupported['example'].proof_types_supported.attestation must be an object");

    class ProofTypeConfiguration {}
    ProofTypeConfiguration.prototype.key_attestations_required = { key_storage: [] };
    expect(() => new Configuration({
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
    })).to.throw("features.openid4vci.credentialConfigurationsSupported['example'].proof_types_supported.attestation.key_attestations_required.key_storage must be a non-empty array of non-empty strings");
  });

  it('does not mutate frozen configuration input', () => {
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

    expect(configuration.claims.profile).to.eql({ name: null });
    expect(configuration.clientAuthSigningAlgValues).to.eql(['RS256']);
    expect(configuration.scopes).to.eql(new Set(['openid', 'profile']));
    expect(input.claims.profile).to.eql(['name']);
    expect(input.enabledJWA.clientAuthSigningAlgValues).to.eql(['HS256', 'RS256']);
    expect(input.scopes).to.eql(['openid']);
  });

  it('copies Set configuration input before normalization', () => {
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

    expect(configuration.acrValues).not.to.equal(input.acrValues);
    expect(configuration.clientAuthMethods).not.to.equal(input.clientAuthMethods);
    expect(configuration.extraParams).not.to.equal(input.extraParams);
    expect(configuration.features.ciba.deliveryModes).not.to.equal(input.features.ciba.deliveryModes);
    expect(configuration.scopes).not.to.equal(input.scopes);
    expect(configuration.subjectTypes).not.to.equal(input.subjectTypes);
    expect(input.scopes).to.eql(new Set(['openid']));
    expect(configuration.scopes).to.eql(new Set(['openid', 'profile']));
  });

  it('checks that a feature configuration property is valid', () => {
    expect(() => {
      new Configuration({
        features: {
          foo: {},
        },
      });
    }).to.throw('Unknown feature configuration: foo');
  });

  it('can validate feature configuration after construction', () => {
    const configuration = new Configuration();
    configuration.features.unknown = {};

    expect(() => configuration.logDraftNotice())
      .to.throw('Unknown feature configuration: unknown');
  });

  it('checks that a stable feature does not have an ack', () => {
    expect(() => {
      new Configuration({
        features: {
          deviceFlow: {
            enabled: true,
            ack: 'draft-01',
          },
        },
      });
    }).to.throw("deviceFlow feature is now stable, the ack draft-01 is no longer valid. Check the stable feature's configuration for any breaking changes.");
  });

  it('accepts stable and acknowledged experimental features together', () => {
    expect(() => {
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
    }).not.to.throw();
  });

  it('checks that a feature configuration is not a boolean', () => {
    expect(() => {
      new Configuration({
        features: {
          devInteractions: false,
        },
      });
    }).to.throw('Features are not enabled/disabled with a boolean value. See the documentation for more details.');
    expect(() => {
      new Configuration({
        features: {
          devInteractions: true,
        },
      });
    }).to.throw('Features are not enabled/disabled with a boolean value. See the documentation for more details.');
  });

  it('checks that cookies.long.sameSite is none when configuring enableHttpPostMethods', () => {
    expect(new Configuration().enableHttpPostMethods).to.be.false;
    expect(new Configuration({ enableHttpPostMethods: false }).enableHttpPostMethods).to.be.false;
    expect(new Configuration({
      enableHttpPostMethods: true,
      cookies: {
        long: {
          sameSite: 'none',
        },
      },
    }).enableHttpPostMethods).to.be.true;
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
    expect(() => {
      new Configuration({
        enableHttpPostMethods: true,
      });
    }).to.throw('HTTP POST Method support requires that cookies.long.sameSite is set to none');
    expect(() => {
      new Configuration({
        enableHttpPostMethods: true,
        cookies: {
          long: {
            sameSite: 'Lax',
          },
        },
      });
    }).to.throw('HTTP POST Method support requires that cookies.long.sameSite is set to none');
  });

  describe('fetchResponseBodyLimits', () => {
    it('accepts valid finite limits', () => {
      const conf = new Configuration({
        fetchResponseBodyLimits: {
          'client_id metadata document': 1024,
          jwks_uri: 10240,
          sector_identifier_uri: 2048,
        },
      });
      expect(conf.fetchResponseBodyLimits.jwks_uri).to.equal(10240);
    });

    it('accepts Infinity (no limit)', () => {
      const conf = new Configuration({
        fetchResponseBodyLimits: {
          jwks_uri: Infinity,
        },
      });
      expect(conf.fetchResponseBodyLimits.jwks_uri).to.equal(Infinity);
    });

    it('rejects negative values', () => {
      expect(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: -1,
          },
        });
      }).to.throw('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity');
    });

    it('rejects non-number values', () => {
      expect(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: '1024',
          },
        });
      }).to.throw('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity');
    });

    it('rejects null values', () => {
      expect(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: null,
          },
        });
      }).to.throw('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity');
    });

    it('rejects NaN', () => {
      expect(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: NaN,
          },
        });
      }).to.throw('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity');
    });

    it('rejects floats', () => {
      expect(() => {
        new Configuration({
          fetchResponseBodyLimits: {
            jwks_uri: 10.5,
          },
        });
      }).to.throw('fetchResponseBodyLimits."jwks_uri" must be a non-negative safe integer or Infinity');
    });
  });
});
