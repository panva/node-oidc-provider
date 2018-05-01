const Provider = require('../../lib');
const { TestAdapter } = require('../models');

const { AdapterTest } = Provider;

describe('AdapterTest', () => {
  it('passes with the default MemoryAdapter', async () => {
    const provider = new Provider('http://localhost');
    await provider.initialize();
    const test = new AdapterTest(provider);
    await test.execute();
  });

  it('passes with the TestAdapter', async () => {
    const provider = new Provider('http://localhost');
    await provider.initialize({
      adapter: TestAdapter,
    });
    const test = new AdapterTest(provider);
    await test.execute();
  });
});
