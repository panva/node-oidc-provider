const got = require('got');
const CacheableLookup = require('cacheable-lookup');
const QuickLRU = require('quick-lru');

const pickBy = require('./_/pick_by');
const instance = require('./weak_cache');

const cacheable = new CacheableLookup({
  cache: new QuickLRU({ maxSize: 1000 }),
});

module.exports = async function request(options) {
  Object.assign(options, {
    url: new URL(options.url),
    headers: options.headers || {},
  });
  // eslint-disable-next-line no-param-reassign
  options.headers['user-agent'] = undefined;
  const { timeout, agent, lookup } = instance(this).configuration('httpOptions')(new URL(options.url));
  const helperOptions = pickBy({ timeout, agent, lookup }, Boolean);

  if (helperOptions.timeout !== undefined && typeof helperOptions.timeout !== 'number') {
    throw new TypeError('"timeout" http request option must be a number');
  }

  if (helperOptions.agent !== undefined && typeof helperOptions.agent !== 'number') {
    helperOptions.agent = { [options.url.protocol.slice(0, -1)]: helperOptions.agent };
  }

  if (helperOptions.lookup !== undefined && typeof helperOptions.lookup !== 'function') {
    throw new TypeError('"lookup" http request option must be a function');
  }

  return got({
    ...options,
    followRedirect: false,
    retry: 0,
    throwHttpErrors: false,
    timeout: 2500,
    lookup: cacheable.lookup,
    ...helperOptions,
  });
};
