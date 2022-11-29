/* eslint-disable no-param-reassign */

import { expect } from 'chai';
import sinon from 'sinon';

import Provider from '../../lib/index.js';
import { InvalidClientMetadata } from '../../lib/helpers/errors.js';

describe('extraClientMetadata configuration', () => {
  it('allows for properties to be added to client schema and have them synchronously validated', async () => {
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

    expect(calls.length).to.eql(6);

    expect(calls[0].calledWith(undefined, 'foo', undefined)).to.be.true;
    expect(calls[1].calledWith(undefined, 'bar', undefined)).to.be.true;
    expect(calls[2].calledWith(undefined, 'foo_bar', undefined)).to.be.true;

    expect(calls[3].calledWith(undefined, 'foo', 'one')).to.be.true;
    expect(calls[4].calledWith(undefined, 'bar', 'two')).to.be.true;
    expect(calls[5].calledWith(undefined, 'foo_bar', 'three')).to.be.true;

    const client = await provider.Client.find('client-2');
    expect(client).to.have.property('foo_bar');
    expect(client.metadata()).to.have.property('foo_bar');
  });

  it('can be used to assign standard properties depending on the value of a custom one', async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(ctx, key, value, metadata) {
          expect(key).to.eql('foo');
          expect(value).to.eql(undefined);
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
    expect(client).to.have.property('foo', 'default');
    expect(client).to.have.property('clientName', 'test RP');
  });

  it('should not allow props to be added without them being allowed', async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['bar'],
        validator(ctx, key, value, metadata) {
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
    expect(client).not.to.have.property('foo');
  });

  it('should not allow to update the client so that its invalid', async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(ctx, key, value, metadata) {
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
      expect(err).to.have.property('message', 'invalid_client_metadata');
      expect(err).to.have.property('error_description', 'client_secret is mandatory property');
    }
  });

  it('can be used to add validations to existing standard properties', async () => {
    const validator = sinon.spy();
    const provider = new Provider('http://localhost:3000', { // eslint-disable-line no-new
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

    expect(validator.calledOnce).to.be.true;
    expect(validator.calledWith(undefined, 'client_name', undefined)).to.be.true;
  });

  it('should throw regular errors during #find()', async () => {
    try {
      const provider = new Provider('http://localhost:3000', { // eslint-disable-line no-new
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
      expect(err).to.have.property('message', 'invalid_client_metadata');
      expect(err).to.have.property('error_description', 'invalid client_description name provided');
    }
  });
});
