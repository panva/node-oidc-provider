/* eslint-disable no-new */

const { expect } = require('chai');

const Provider = require('../../lib');

describe('Provider configuration', () => {
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
      }).to.throw(Error).with.property('error_description', 'client_id must be unique for statically configured clients');
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
    it('only accepts arrays and sets', () => {
      new Provider('http://localhost:3000', { extraParams: ['foo', 'bar'] });
      new Provider('http://localhost:3000', { extraParams: new Set(['foo', 'bar']) });
      expect(() => {
        new Provider('http://localhost:3000', { extraParams: { foo: true } });
      }).to.throw('extraParams must be an Array or Set');
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

  describe('dynamicScopes', () => {
    it('only accepts arrays and sets', () => {
      new Provider('http://localhost:3000', { dynamicScopes: [/foo/] });
      new Provider('http://localhost:3000', { dynamicScopes: new Set([/foo/]) });
      expect(() => {
        new Provider('http://localhost:3000', { dynamicScopes: { foo: true } });
      }).to.throw('dynamicScopes must be an Array or Set');
    });
  });

  describe('claims', () => {
    it('only accepts maps and objects', () => {
      new Provider('http://localhost:3000', { claims: { foo: null } });
      new Provider('http://localhost:3000', { claims: new Map(Object.entries({ foo: null })) });
      expect(() => {
        const claims = new class {
          constructor() {
            this.foo = null;
          }
        }();

        new Provider('http://localhost:3000', { claims });
      }).to.throw('claims must be a plain javascript object or Map');
    });
  });

  describe('ttl', () => {
    it('checks the values are positive safe integers or functions', () => {
      let throws = [
        () => { new Provider('http://localhost:3000', { ttl: { default: 0 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: Number.MAX_SAFE_INTEGER + 1 } }); },
        () => { new Provider('http://localhost:3000', { ttl: { default: -1 } }); },
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
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: Infinity } }); },
        () => { new Provider('http://localhost:3000', { ttl: { AccessToken: '1' } }); },
        () => { new Provider('http://localhost:3000', { ttl: { async AccessToken() { return 600; } } }); },
        () => { new Provider('http://localhost:3000', { ttl: { * AccessToken() { yield 600; } } }); },
      ];

      throws.forEach((fn) => {
        expect(fn).to.throw('ttl.AccessToken must be a positive integer or a regular function returning one');
      });
    });
  });

  ['token', 'introspection', 'revocation'].forEach((endpoint) => {
    const prop = `${endpoint}EndpointAuthMethods`;
    it(`validates configuration ${prop} members`, () => {
      expect(() => {
        new Provider('http://localhost:3000', { [prop]: ['foo'] });
      }).to.throw(`only supported ${prop} are [none,client_secret_basic,client_secret_jwt,client_secret_post,private_key_jwt,tls_client_auth,self_signed_tls_client_auth]`);
    });
  });

  describe('pkceMethods', () => {
    it('validates configuration pkceMethods members', () => {
      const throws = [
        () => {
          new Provider('http://localhost:3000', {
            pkceMethods: ['S256', 'plain', 'foobar'],
          });
        },
        () => {
          new Provider('http://localhost:3000', {
            pkceMethods: ['foobar'],
          });
        },
      ];

      throws.forEach((fn) => {
        expect(fn).to.throw('only plain and S256 code challenge methods are supported');
      });
    });

    it('validates configuration pkceMethods presence', () => {
      expect(() => {
        new Provider('http://localhost:3000', {
          pkceMethods: [],
        });
      }).to.throw('pkceMethods must not be empty');
    });

    it('validates configuration pkceMethods type', () => {
      expect(() => {
        new Provider('http://localhost:3000', {
          pkceMethods: 'public',
        });
      }).to.throw('pkceMethods must be an array');
    });
  });
});
