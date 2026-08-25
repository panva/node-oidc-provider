import { expect } from 'chai';

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
    it('does not leak enabled feature parameters to a subsequent Provider', () => {
      const enabled = providerWithFeatureGrantParameters('http://enabled.example.com');
      const disabled = providerWithoutFeatureGrantParameters('http://disabled.example.com');

      expect(authorizationCodeGrantParameters(enabled)).to.include('resource').and.include('authorization_details');
      expect(authorizationCodeGrantParameters(disabled)).not.to.include('resource').and.not.include('authorization_details');
      expect(authorizationCodeParameters).not.to.include('resource').and.not.include('authorization_details');
    });

    it('does not add disabled feature parameters based on Provider construction order', () => {
      const disabled = providerWithoutFeatureGrantParameters('http://disabled-first.example.com');
      const enabled = providerWithFeatureGrantParameters('http://enabled-second.example.com');

      expect(authorizationCodeGrantParameters(disabled)).not.to.include('resource').and.not.include('authorization_details');
      expect(authorizationCodeGrantParameters(enabled)).to.include('resource').and.include('authorization_details');
      expect(authorizationCodeParameters).not.to.include('resource').and.not.include('authorization_details');
    });
  });

  describe('clients', () => {
    it('may contain static clients when these have at least the client_id', () => {
      expect(() => {
        new Provider('http://localhost:3000', {
          clients: [null],
        });
      }).to.throw(Error).with.property('error_description', 'client_id is mandatory property for statically configured clients');
      expect(() => {
        new Provider('http://localhost:3000', {
          clients: [
            {},
          ],
        });
      }).to.throw(Error).with.property('error_description', 'client_id is mandatory property for statically configured clients');
    });
    it('client_id must be unique amongst the static clients', () => {
      expect(() => {
        new Provider('http://localhost:3000', {
          clients: [
            { client_id: 'foo' },
            { client_id: 'foo' },
          ],
        });
      }).to.throw(Error).with.property('error_description', 'client_id must be unique amongst statically configured clients');
    });
  });

  describe('acrValues', () => {
    it('only accepts arrays and sets', () => {
      new Provider('http://localhost:3000', { acrValues: ['bronze', 'silver'] });
      new Provider('http://localhost:3000', { acrValues: new Set(['bronze', 'silver']) });
      expect(() => {
        new Provider('http://localhost:3000', { acrValues: { bronze: true } });
      }).to.throw('acrValues must be an Array or Set');
    });
  });

  describe('subjectTypes', () => {
    it('only accepts arrays and sets', () => {
      new Provider('http://localhost:3000', { subjectTypes: ['public'] });
      new Provider('http://localhost:3000', { subjectTypes: new Set(['public']) });
      expect(() => {
        new Provider('http://localhost:3000', { subjectTypes: { bronze: true } });
      }).to.throw('subjectTypes must be an Array or Set');
    });
  });

  describe('extraParams', () => {
    it('accepts arrays, sets, or plain objects with validators', () => {
      new Provider('http://localhost:3000', { extraParams: ['foo', 'bar'] });
      new Provider('http://localhost:3000', { extraParams: new Set(['foo', 'bar']) });
      new Provider('http://localhost:3000', { extraParams: { foo: null } });
      new Provider('http://localhost:3000', { extraParams: { foo: undefined } });
      new Provider('http://localhost:3000', { extraParams: { foo() {} } });
      new Provider('http://localhost:3000', { extraParams: { async foo() {} } });
      expect(() => {
        new Provider('http://localhost:3000', { extraParams: Boolean });
      }).to.throw('extraParams must be an Array or Set');
      expect(() => {
        new Provider('http://localhost:3000', { extraParams: { foo: true } });
      }).to.throw('invalid extraParams.foo type, it must be a function, null, or undefined');
      expect(() => {
        new Provider('http://localhost:3000', { extraParams: { * foo() {} } });
      }).to.throw('invalid extraParams.foo type, it must be a function, null, or undefined');
    });
  });

  describe('scopes', () => {
    it('only accepts arrays and sets', () => {
      new Provider('http://localhost:3000', { scopes: ['foo', 'bar'] });
      new Provider('http://localhost:3000', { scopes: new Set(['foo', 'bar']) });
      expect(() => {
        new Provider('http://localhost:3000', { scopes: { foo: true } });
      }).to.throw('scopes must be an Array or Set');
    });
  });

  describe('ttl', () => {
    it('checks the values are positive safe integers or functions', () => {
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
        expect(fn).to.throw('ttl.default must be a positive integer or a regular function returning one');
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
        expect(fn).to.throw('ttl.AccessToken must be a positive integer or a regular function returning one');
      });

      let okay = [
        () => { new Provider('http://localhost:3000', { ttl: { default: 1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: Number.MAX_SAFE_INTEGER } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default() { return 600; } } }); },
      ];

      okay.forEach((fn) => {
        expect(fn).not.to.throw();
      });

      okay = [
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: 1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: Number.MAX_SAFE_INTEGER } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken() { return 600; } } }); },
      ];

      okay.forEach((fn) => {
        expect(fn).not.to.throw();
      });
    });
  });

  it('validates configuration clientAuthMethods members', () => {
    expect(() => {
      new Provider('http://localhost:3000', { clientAuthMethods: ['foo'] });
    }).to.throw('only supported clientAuthMethods are \'none\', \'client_secret_basic\', \'client_secret_jwt\', \'client_secret_post\', and \'private_key_jwt\'');
  });
});
