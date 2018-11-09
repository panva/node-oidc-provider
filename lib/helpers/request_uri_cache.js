const crypto = require('crypto');
const assert = require('assert');

const LRU = require('lru-cache');

const httpRequest = require('./http');
const epochTime = require('./epoch_time');

class RequestUriCache {
  constructor(provider) {
    this.cache = new LRU(100);
    this.provider = provider;
  }

  async resolve(requestUri) {
    const { cache } = this;
    const cacheKey = crypto.createHash('sha256').update(requestUri).digest('hex');
    const cached = cache.get(cacheKey);

    if (cached) {
      return cached;
    }

    const { statusCode, headers, body } = await httpRequest.get(
      requestUri,
      this.provider.httpOptions(),
    );

    assert.deepEqual(
      statusCode, 200,
      `unexpected request_uri statusCode, expected 200, got ${statusCode}`,
    );

    let cacheDuration;
    if (headers.expires) {
      cacheDuration = 1000 * ((Date.parse(headers.expires) / 1000) - epochTime());
    } else if (headers['cache-control'] && /max-age=(\d+)/.test(headers['cache-control'])) {
      cacheDuration = parseInt(RegExp.$1, 10) * 1000;
    }

    cache.set(cacheKey, body, cacheDuration);

    return body;
  }
}

module.exports = RequestUriCache;
