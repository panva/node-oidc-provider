import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import Provider from '../../lib/index.js';
import { InvalidClientMetadata } from '../../lib/helpers/errors.js';

describe('extraClientMetadata configuration', () => {
  it('allows for properties to be added to client schema and have them synchronously validated', { timeout: 3000 }, async () => {
    const validator = sinon.spy();
    const properties = ['foo', 'bar', 'foo_bar'];
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties,
        validator,
      },
      clients: [
        {
          client_id: 'client-1',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
        },
        {
          client_id: 'client-2',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
          foo: 'one',
          bar: 'two',
          foo_bar: 'three',
        },
      ],
    });

    await provider.Client.find('client-1');
    await provider.Client.find('client-2');

    const calls = validator.getCalls();

    assert.deepEqual(calls.length, 6);

    assert.equal(calls[0].calledWith(undefined, 'foo', undefined), true);
    assert.equal(calls[1].calledWith(undefined, 'bar', undefined), true);
    assert.equal(calls[2].calledWith(undefined, 'foo_bar', undefined), true);

    assert.equal(calls[3].calledWith(undefined, 'foo', 'one'), true);
    assert.equal(calls[4].calledWith(undefined, 'bar', 'two'), true);
    assert.equal(calls[5].calledWith(undefined, 'foo_bar', 'three'), true);

    const client = await provider.Client.find('client-2');
    assert.ok('foo_bar' in Object(client));
    assert.ok('foo_bar' in Object(client.metadata()));
  });

  it('can be used to assign standard properties depending on the value of a custom one', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(_ctx, key, value, metadata) {
          assert.deepEqual(key, 'foo');
          assert.deepEqual(value, undefined);
          metadata[key] = 'default';
          metadata.client_name = 'test RP';
        },
      },
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
        },
      ],
    });

    const client = await provider.Client.find('client');
    ((actual) => { assert.ok('foo' in Object(actual)); assert.equal(actual.foo, 'default'); })(client);
    ((actual) => { assert.ok('clientName' in Object(actual)); assert.equal(actual.clientName, 'test RP'); })(client);
  });

  it('should not allow props to be added without them being allowed', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['bar'],
        validator(_ctx, _key, _value, metadata) {
          metadata.foo = 'foo';
        },
      },
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
        },
      ],
    });

    const client = await provider.Client.find('client');
    assert.ok(!('foo' in Object(client)));
  });

  it('should not allow to update the client so that its invalid', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(_ctx, _key, _value, metadata) {
          metadata.client_secret = undefined;
        },
      },
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          token_endpoint_auth_method: 'client_secret_basic',
          redirect_uris: ['http://rp.example.com/cb'],
        },
      ],
    });

    try {
      await provider.Client.find('client');
      throw new Error('expected a throw from the above');
    } catch (err) {
      ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_client_metadata'); })(err);
      ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'client_secret is mandatory property'); })(err);
    }
  });

  it('can be used to add validations to existing standard properties', { timeout: 3000 }, async () => {
    const validator = sinon.spy();
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['client_name'],
        validator,
      },
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
        },
      ],
    });

    await provider.Client.find('client');

    assert.equal(validator.calledOnce, true);
    assert.equal(validator.calledWith(undefined, 'client_name', undefined), true);
  });

  it('should allow customization to set grant_types that get auto-fixed based on response_types', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(_ctx, _key, _value, metadata) {
          metadata.grant_types = ['implicit'];
        },
      },
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['https://rp.example.com/cb'],
        },
      ],
    });

    const client = await provider.Client.find('client');
    ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, ['authorization_code']); })(client.metadata());
  });

  it('should not allow customization to remove redirect_uris when response_types need them', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(_ctx, _key, _value, metadata) {
          metadata.redirect_uris = undefined;
        },
      },
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['https://rp.example.com/cb'],
        },
      ],
    });

    try {
      await provider.Client.find('client');
      throw new Error('expected a throw from the above');
    } catch (err) {
      ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_redirect_uri'); })(err);
      ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'redirect_uris is mandatory property'); })(err);
    }
  });

  it('allows the validator to change standard properties before validation runs', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(_ctx, _key, _value, metadata) {
          metadata.token_endpoint_auth_method = 'none';
        },
      },
      clients: [
        {
          client_id: 'client',
          redirect_uris: ['https://rp.example.com/cb'],
        },
      ],
    });

    const client = await provider.Client.find('client');
    ((actual) => { assert.ok('tokenEndpointAuthMethod' in Object(actual)); assert.equal(actual.tokenEndpointAuthMethod, 'none'); })(client);
  });

  it('should throw regular errors during #find()', { timeout: 3000 }, async () => {
    try {
      const provider = new Provider('http://localhost:3000', {
        extraClientMetadata: {
          properties: ['client_description'],
          validator() {
            throw new InvalidClientMetadata('invalid client_description name provided');
          },
        },
        clients: [
          {
            client_name: 'foo',
            client_id: 'client',
            client_secret: 'bar',
            redirect_uris: ['http://rp.example.com/cb'],
          },
        ],
      });

      await provider.Client.find('client');

      throw new Error('expected a throw from the above');
    } catch (err) {
      ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_client_metadata'); })(err);
      ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'invalid client_description name provided'); })(err);
    }
  });

  it('rejects thenables returned by regular validators', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator() {
          return Promise.resolve();
        },
      },
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
        },
      ],
    });

    try {
      await provider.Client.find('client');
      throw new Error('expected a throw from the above');
    } catch (err) {
      ((actual) => { assert.ok(actual instanceof TypeError); })(err);
      ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'extraClientMetadata.validator must be a synchronous function'); })(err);
    }
  });
});
