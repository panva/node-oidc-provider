const MemoryAdapter = require('../adapters/memory_adapter');

const instance = require('./weak_cache');
const attention = require('./attention');

module.exports = function initializeAdapter(adapter = MemoryAdapter) {
  if (adapter === MemoryAdapter) {
    attention.warn('a quick start development-only in-memory adapter is used, you MUST change it in'
    + ' order to not lose all stateful provider data upon restart and to be able to share these'
    + ' between processes');
  }

  if (!adapter.prototype || !adapter.prototype.constructor.name) {
    throw new Error(
      'Expected "adapter" to be a constructor, provide a valid adapter in Provider config.',
    );
  }

  instance(this).Adapter = adapter;
};
