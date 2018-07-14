const Provider = require('../../lib');
const { TestAdapter } = require('../models');

const { AdapterTest } = Provider;
const clientFactory = () => 'client';
const client = {
  client_id: 'client',
  client_secret: 'secret',
  redirect_uris: ['https://rp.example.com/cb'],
};

describe('AdapterTest', () => {
  it('passes with the default MemoryAdapter', async () => {
    const provider = new Provider('http://localhost', { features: { deviceCode: true } });
    await provider.initialize({
      clients: [client],
    });
    const test = new AdapterTest(provider, undefined, clientFactory);
    await test.execute();
  });

  it('passes with the TestAdapter', async () => {
    const provider = new Provider('http://localhost', { features: { deviceCode: true } });
    await provider.initialize({
      clients: [client],
      adapter: TestAdapter,
    });
    const test = new AdapterTest(provider, undefined, clientFactory);
    await test.execute();
  });
});
