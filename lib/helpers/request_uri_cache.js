const LRU = require('lru-cache');
const crypto = require('crypto');
const assert = require('assert');
const httpRequest = require('./http');
const epochTime = require('./epoch_time');

class RequestUriCache {
  constructor(provider) {
    this.cache = new LRU(100);
    this.provider = provider;
  }

  resolve(requestUri) {
    const { cache } = this;
    const cacheKey = crypto.createHash('sha256').update(requestUri).digest('hex');
    const cached = cache.get(cacheKey);

    if (cached) return Promise.resolve(cached);

    return httpRequest.get(requestUri, this.provider.httpOptions())
      .then(({ statusCode, headers, body }) => {
        assert.equal(
          statusCode, 200,
          `unexpected request_uri statusCode, expected 200, got ${statusCode}`,
        );

        let cacheDuration;
        if (headers.expires) {
          cacheDuration = 1000 * ((Date.parse(headers.expires) / 1000) - epochTime());
        } else if (headers['cache-control'] && headers['cache-control'].match(/max-age=(\d+)/)) {
          cacheDuration = parseInt(RegExp.$1, 10) * 1000;
        }

        cache.set(cacheKey, body, cacheDuration);

        return body;
      });
  }
}

module.exports = RequestUriCache;
