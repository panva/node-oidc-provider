const util = require('node:util');

const MemoryAdapter = require('../adapters/memory_adapter.js');

const instance = require('./weak_cache.js');
const attention = require('./attention.js');
const { isConstructable } = require('./type_validators.js');

module.exports = function initializeAdapter(adapter = MemoryAdapter) {
  if (adapter === MemoryAdapter) {
    attention.warn('a quick start development-only in-memory adapter is used, you MUST change it in'
    + ' order to not lose all stateful provider data upon restart and to be able to share these'
    + ' between processes');
  }

  const constructable = isConstructable(adapter);
  const executable = typeof adapter === 'function' && !util.types.isAsyncFunction(adapter);
  const valid = constructable || executable;

  if (!valid) {
    throw new Error('Expected "adapter" to be a constructor or a factory function, provide a valid adapter in Provider config.');
  }

  instance(this).Adapter = adapter;
};
