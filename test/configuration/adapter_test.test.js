const Provider = require('../../lib');
const { TestAdapter } = require('../models');

const { AdapterTest } = Provider;

describe('AdapterTest', () => {
  it('passes with the default MemoryAdapter', () => {
    const provider = new Provider('http://localhost');

    return provider.initialize().then(() => {
      const test = new AdapterTest(provider);
      return test.execute();
    });
  });

  it('passes with the TestAdapter', () => {
    const provider = new Provider('http://localhost');
    return provider.initialize({
      adapter: TestAdapter,
    }).then(() => {
      const test = new AdapterTest(provider);
      return test.execute();
    });
  });
});
