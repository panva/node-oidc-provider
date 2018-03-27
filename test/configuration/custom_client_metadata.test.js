/* eslint-disable no-param-reassign */

const Provider = require('../../lib');
const { expect } = require('chai');
const sinon = require('sinon');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('extraClientMetadata configuration', () => {
  it('allows for properties to be added to client schema and have them synchronously validated', async () => {
    const validator = sinon.spy();
    const properties = ['foo', 'bar', 'foo_bar'];
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties,
        validator,
      },
    });

    await provider.initialize({
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
    const calls = validator.getCalls();

    expect(calls.length).to.eql(6);

    expect(calls[0].calledWith('foo', undefined)).to.be.true;
    expect(calls[1].calledWith('bar', undefined)).to.be.true;
    expect(calls[2].calledWith('foo_bar', undefined)).to.be.true;

    expect(calls[3].calledWith('foo', 'one')).to.be.true;
    expect(calls[4].calledWith('bar', 'two')).to.be.true;
    expect(calls[5].calledWith('foo_bar', 'three')).to.be.true;

    const client = await provider.Client.find('client-2');
    expect(client).to.have.property('fooBar');
  });

  it('can be used assign standard properties depending on the value of a custom one', async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['foo'],
        validator(key, value, metadata) {
          expect(key).to.eql('foo');
          expect(value).to.eql(undefined);
          metadata[key] = 'default';
          metadata.client_name = 'test RP';
        },
      },
    });

    await provider.initialize({
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

  it('should not allow props to be added without them being whitelisted', async () => {
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['bar'],
        validator(key, value, metadata) {
          metadata.foo = 'foo';
        },
      },
    });

    await provider.initialize({
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

  it('can be used to add validations to existing standard properties', async () => {
    const validator = sinon.spy();
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['client_name'],
        validator,
      },
    });

    await provider.initialize({
      clients: [
        {
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
        },
      ],
    });

    expect(validator.calledOnce).to.be.true;
    expect(validator.calledWith('client_name', undefined)).to.be.true;
  });

  it('should re-throw errors', async () => {
    const { InvalidClientMetadata } = Provider;
    const provider = new Provider('http://localhost:3000', {
      extraClientMetadata: {
        properties: ['client_description'],
        validator() {
          throw new InvalidClientMetadata('invalid client_description name provided');
        },
      },
    });

    return provider.initialize({
      clients: [
        {
          client_name: 'foo',
          client_id: 'client',
          client_secret: 'bar',
          redirect_uris: ['http://rp.example.com/cb'],
        },
      ],
    }).then(fail, (err) => {
      expect(err).to.have.property('message', 'invalid_client_metadata');
      expect(err).to.have.property('error_description', 'invalid client_description name provided');
    });
  });
});
