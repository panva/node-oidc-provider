'use strict';
const LRU = require('lru-cache');
const crypto = require('crypto');
const assert = require('assert');
const got = require('got');

class RequestUriCache {
  constructor(provider) {
    this.cache = new LRU(100);
    this.provider = provider;
  }

  * resolve(requestUri) {
    const cache = this.cache;
    const cacheKey = crypto.createHash('sha256').update(requestUri).digest('hex');
    const cached = cache.get(cacheKey);

    if (cached) return cached;

    const request = yield got(requestUri, {
      headers: {
        'User-Agent': this.provider.userAgent(),
      },
      timeout: this.provider.configuration('timeouts.request_uri'),
      retries: 0,
      followRedirect: false,
    });

    assert.ok(request.statusCode === 200,
      `unexpected request_uri statusCode, expected 200, got ${request.statusCode}`);

    const cacheControl = request.headers['cache-control'];
    let maxAge = 15 * 60 * 1000;

    if (cacheControl && cacheControl.match(/max-age=(\d+)/)) {
      maxAge = parseInt(RegExp.$1, 10) * 1000 || maxAge;
    }

    cache.set(cacheKey, request.body, maxAge);

    return request.body;
  }
}

module.exports = RequestUriCache;
