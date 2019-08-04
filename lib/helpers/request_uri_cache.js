const crypto = require('crypto');
const { strict: assert } = require('assert');
const { STATUS_CODES } = require('http');

const LRU = require('lru-cache');

const epochTime = require('./epoch_time');
const request = require('./request');

class RequestUriCache {
  constructor(provider) {
    this.cache = new LRU(100);
    this.provider = provider;
  }

  async resolveUrn(requestUri) { // eslint-disable-line
    throw new Error('resolving request_uri by URN is not implemented');
  }

  async resolveWebUri(requestUri) {
    const { cache } = this;
    const cacheKey = crypto.createHash('sha256').update(requestUri).digest('hex');
    const cached = cache.get(cacheKey);

    if (cached) {
      return cached;
    }

    const { statusCode, headers, body } = await request.call(this.provider, {
      method: 'GET',
      url: requestUri,
      headers: {
        Accept: 'application/jwt',
      },
    });

    assert.equal(
      statusCode, 200,
      `unexpected request_uri response status code, expected 200 OK, got ${statusCode} ${STATUS_CODES[statusCode]}`,
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
