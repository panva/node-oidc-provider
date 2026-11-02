import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';
import { parameters as authorizationCodeParameters } from '../../lib/actions/grants/authorization_code.js';
import instance from '../../lib/helpers/weak_cache.js';

function providerWithFeatureGrantParameters(issuer) {
  return new Provider(issuer, {
    features: {
      resourceIndicators: { enabled: true },
      richAuthorizationRequests: {
        enabled: true,
        types: {
          example: { validate() {} },
        },
      },
    },
  });
}

function providerWithoutFeatureGrantParameters(issuer) {
  return new Provider(issuer, {
    features: {
      resourceIndicators: { enabled: false },
      richAuthorizationRequests: { enabled: false },
    },
  });
}

function authorizationCodeGrantParameters(provider) {
  return instance(provider).grantTypeParams.get('authorization_code');
}

describe('Provider configuration', () => {
  describe('grant parameters', () => {
    it('does not leak enabled feature parameters to a subsequent Provider', { timeout: 3000 }, () => {
      const enabled = providerWithFeatureGrantParameters('http://enabled.example.com');
      const disabled = providerWithoutFeatureGrantParameters('http://disabled.example.com');

      ((actual) => { assert.ok(actual.has('resource')); assert.ok(actual.has('authorization_details')); })(authorizationCodeGrantParameters(enabled));
      ((actual) => { assert.ok(!(actual.has('resource'))); assert.ok(!(actual.has('authorization_details'))); })(authorizationCodeGrantParameters(disabled));
      ((actual) => { assert.ok(!(actual.has('resource'))); assert.ok(!(actual.has('authorization_details'))); })(authorizationCodeParameters);
    });

    it('does not add disabled feature parameters based on Provider construction order', { timeout: 3000 }, () => {
      const disabled = providerWithoutFeatureGrantParameters('http://disabled-first.example.com');
      const enabled = providerWithFeatureGrantParameters('http://enabled-second.example.com');

      ((actual) => { assert.ok(!(actual.has('resource'))); assert.ok(!(actual.has('authorization_details'))); })(authorizationCodeGrantParameters(disabled));
      ((actual) => { assert.ok(actual.has('resource')); assert.ok(actual.has('authorization_details')); })(authorizationCodeGrantParameters(enabled));
      ((actual) => { assert.ok(!(actual.has('resource'))); assert.ok(!(actual.has('authorization_details'))); })(authorizationCodeParameters);
    });
  });

  describe('clients', () => {
    it('may contain static clients when these have at least the client_id', { timeout: 3000 }, () => {
      ((actual) => { assert.throws(actual, (error) => { assert.ok(error instanceof Error); assert.ok('error_description' in Object(error)); assert.equal(error.error_description, 'client_id is mandatory property for statically configured clients'); return true; }); })(() => {
        new Provider('http://localhost:3000', {
          clients: [null],
        });
      });
      ((actual) => { assert.throws(actual, (error) => { assert.ok(error instanceof Error); assert.ok('error_description' in Object(error)); assert.equal(error.error_description, 'client_id is mandatory property for statically configured clients'); return true; }); })(() => {
        new Provider('http://localhost:3000', {
          clients: [
            {},
          ],
        });
      });
    });
    it('client_id must be unique amongst the static clients', { timeout: 3000 }, () => {
      ((actual) => { assert.throws(actual, (error) => { assert.ok(error instanceof Error); assert.ok('error_description' in Object(error)); assert.equal(error.error_description, 'client_id must be unique amongst statically configured clients'); return true; }); })(() => {
        new Provider('http://localhost:3000', {
          clients: [
            { client_id: 'foo' },
            { client_id: 'foo' },
          ],
        });
      });
    });
  });

  describe('acrValues', () => {
    it('only accepts arrays and sets', { timeout: 3000 }, () => {
      new Provider('http://localhost:3000', { acrValues: ['bronze', 'silver'] });
      new Provider('http://localhost:3000', { acrValues: new Set(['bronze', 'silver']) });
      assert.throws(() => {
        new Provider('http://localhost:3000', { acrValues: { bronze: true } });
      }, (error) => { assert.ok(error.message.includes('acrValues must be an Array or Set')); return true; });
    });
  });

  describe('subjectTypes', () => {
    it('only accepts arrays and sets', { timeout: 3000 }, () => {
      new Provider('http://localhost:3000', { subjectTypes: ['public'] });
      new Provider('http://localhost:3000', { subjectTypes: new Set(['public']) });
      assert.throws(() => {
        new Provider('http://localhost:3000', { subjectTypes: { bronze: true } });
      }, (error) => { assert.ok(error.message.includes('subjectTypes must be an Array or Set')); return true; });
    });
  });

  describe('extraParams', () => {
    it('accepts arrays, sets, or plain objects with validators', { timeout: 3000 }, () => {
      new Provider('http://localhost:3000', { extraParams: ['foo', 'bar'] });
      new Provider('http://localhost:3000', { extraParams: new Set(['foo', 'bar']) });
      new Provider('http://localhost:3000', { extraParams: { foo: null } });
      new Provider('http://localhost:3000', { extraParams: { foo: undefined } });
      new Provider('http://localhost:3000', { extraParams: { foo() {} } });
      new Provider('http://localhost:3000', { extraParams: { async foo() {} } });
      assert.throws(() => {
        new Provider('http://localhost:3000', { extraParams: Boolean });
      }, (error) => { assert.ok(error.message.includes('extraParams must be an Array or Set')); return true; });
      assert.throws(() => {
        new Provider('http://localhost:3000', { extraParams: { foo: true } });
      }, (error) => { assert.ok(error.message.includes('invalid extraParams.foo type, it must be a function, null, or undefined')); return true; });
      assert.throws(() => {
        new Provider('http://localhost:3000', { extraParams: { * foo() {} } });
      }, (error) => { assert.ok(error.message.includes('invalid extraParams.foo type, it must be a function, null, or undefined')); return true; });
    });
  });

  describe('scopes', () => {
    it('only accepts arrays and sets', { timeout: 3000 }, () => {
      new Provider('http://localhost:3000', { scopes: ['foo', 'bar'] });
      new Provider('http://localhost:3000', { scopes: new Set(['foo', 'bar']) });
      assert.throws(() => {
        new Provider('http://localhost:3000', { scopes: { foo: true } });
      }, (error) => { assert.ok(error.message.includes('scopes must be an Array or Set')); return true; });
    });
  });

  describe('ttl', () => {
    it('checks the values are positive safe integers or functions', { timeout: 3000 }, () => {
      let throws = [
        () => { new Provider('http://localhost:3000', { ttl: { default: 0 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: Number.MAX_SAFE_INTEGER + 1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: -1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: 1.5 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: NaN } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: Infinity } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: '1' } }); },
        () => { new Provider('http://localhost:3000', { ttl: { async default() { return 600; } } }); },
        () => { new Provider('http://localhost:3000', { ttl: { * default() { yield 600; } } }); },
      ];

      throws.forEach((fn) => {
        assert.throws(fn, (error) => { assert.ok(error.message.includes('ttl.default must be a positive integer or a regular function returning one')); return true; });
      });

      throws = [
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: 0 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: Number.MAX_SAFE_INTEGER + 1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: -1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: 1.5 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: NaN } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: Infinity } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: '1' } }); },
        () => { new Provider('http://localhost:3000', { ttl: { async AccessToken() { return 600; } } }); },
        () => { new Provider('http://localhost:3000', { ttl: { * AccessToken() { yield 600; } } }); },
      ];

      throws.forEach((fn) => {
        assert.throws(fn, (error) => { assert.ok(error.message.includes('ttl.AccessToken must be a positive integer or a regular function returning one')); return true; });
      });

      let okay = [
        () => { new Provider('http://localhost:3000', { ttl: { default: 1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: Number.MAX_SAFE_INTEGER } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default() { return 600; } } }); },
      ];

      okay.forEach((fn) => {
        assert.doesNotThrow(fn);
      });

      okay = [
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: 1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: Number.MAX_SAFE_INTEGER } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken() { return 600; } } }); },
      ];

      okay.forEach((fn) => {
        assert.doesNotThrow(fn);
      });
    });
  });

  it('validates configuration clientAuthMethods members', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('http://localhost:3000', { clientAuthMethods: ['foo'] });
    }, (error) => { assert.ok(error.message.includes('only supported clientAuthMethods are \'none\', \'client_secret_basic\', \'client_secret_jwt\', \'client_secret_post\', and \'private_key_jwt\'')); return true; });
  });

  it('requires attestation and DPoP support for combined client authentication', { timeout: 3000 }, () => {
    for (const [attest, dpop] of [[false, false], [true, false], [false, true]]) {
      assert.throws(() => new Provider('http://localhost:3000', {
        clientAuthMethods: ['attest_jwt_client_auth_dpop'],
        features: {
          attestClientAuth: { enabled: attest, challengeSecret: Buffer.alloc(32) },
          dPoP: { enabled: dpop },
        },
      }), (error) => { assert.ok(error.message.includes('only supported clientAuthMethods are')); return true; });
    }

    assert.doesNotThrow(() => new Provider('http://localhost:3000', {
      clientAuthMethods: ['attest_jwt_client_auth_dpop'],
      features: {
        attestClientAuth: { enabled: true, challengeSecret: Buffer.alloc(32) },
        dPoP: { enabled: true, nonceSecret: Buffer.alloc(32) },
      },
    }));
  });

  it('requires a DPoP nonce secret whenever attestation and DPoP are enabled', { timeout: 3000 }, () => {
    for (const dPoP of [undefined, { enabled: true }]) {
      assert.throws(() => new Provider('http://localhost:3000', {
        features: {
          attestClientAuth: { enabled: true, challengeSecret: Buffer.alloc(32) },
          dPoP,
        },
      }), (error) => { assert.ok(error.message.includes('features.dPoP.nonceSecret is required when features.attestClientAuth and features.dPoP are enabled')); return true; });
    }

    for (const [attest, dpop] of [[false, true], [true, false]]) {
      assert.doesNotThrow(() => new Provider('http://localhost:3000', {
        features: {
          attestClientAuth: { enabled: attest, challengeSecret: Buffer.alloc(32) },
          dPoP: { enabled: dpop },
        },
      }));
    }
  });
});
