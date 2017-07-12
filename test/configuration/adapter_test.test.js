const Provider = require('../../lib');
const { TestAdapter } = require('../models');

const { AdapterTest } = Provider;

describe('AdapterTest', function () {
  it('passes with the default MemoryAdapter', function () {
    const provider = new Provider('http://localhost');

    return provider.initialize().then(() => {
      const test = new AdapterTest(provider);
      return test.execute();
    });
  });

  it('passes with the TestAdapter', function () {
    const provider = new Provider('http://localhost');
    return provider.initialize({
      adapter: TestAdapter,
    }).then(() => {
      const test = new AdapterTest(provider);
      return test.execute();
    });
  });
});
