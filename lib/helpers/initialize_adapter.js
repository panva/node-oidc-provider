const MemoryAdapter = require('../adapters/memory_adapter');

const instance = require('./weak_cache');
const attention = require('./attention');

module.exports = async function initializeAdapter(adapter = MemoryAdapter) {
  if (adapter === MemoryAdapter) {
    attention.warn('a quick start development-only MemoryAdapter is used');
  }

  if (adapter.connect) await adapter.connect(this);
  instance(this).Adapter = adapter;
};
