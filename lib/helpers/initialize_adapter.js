const MemoryAdapter = require('../adapters/memory_adapter');

const instance = require('./weak_cache');
const attention = require('./attention');

module.exports = async function initializeAdapter(adapter = MemoryAdapter) {
  if (adapter === MemoryAdapter) {
    attention.warn('a quick start development-only MemoryAdapter is used');
  }
  function isCtor() {
    return !!adapter.prototype && !!adapter.prototype.constructor.name;
  }

  if (!isCtor()) {
    throw new Error(
      "Expected 'adapter' to be a constructor, provide a valid adapter in Provider config.",
    );
  }

  if (adapter.connect) await adapter.connect(this);
  instance(this).Adapter = adapter;
};
