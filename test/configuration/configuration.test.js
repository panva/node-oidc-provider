import { expect } from 'chai';

import Configuration from '../../lib/helpers/configuration.js';

describe('Provider configuration', () => {
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
