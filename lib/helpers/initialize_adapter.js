const instance = require('./weak_cache');
const MemoryAdapter = require('../adapters/memory_adapter');

module.exports = async function initializeAdapter(adapter = MemoryAdapter) {
  if (adapter === MemoryAdapter) {
    console.info('NOTICE: a quick start development-only MemoryAdapter is used'); // eslint-disable-line no-console
  }

  if (adapter.connect) await adapter.connect(this);
  instance(this).Adapter = adapter;
};
