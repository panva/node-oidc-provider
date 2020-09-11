const crypto = require('crypto');
const { strict: assert } = require('assert');
const { STATUS_CODES } = require('http');

const QuickLRU = require('quick-lru');

const request = require('./request');

class RequestUriCache {
  constructor(provider) {
    this.cache = new QuickLRU({ maxSize: 100 });
    this.provider = provider;
  }

  async resolve(requestUri) {
    const { cache } = this;
    const cacheKey = crypto.createHash('sha256').update(requestUri).digest('hex');
    const cached = cache.get(cacheKey);

    if (cached) {
      return cached;
    }

    const { statusCode, body } = await request.call(this.provider, {
      method: 'GET',
      url: requestUri,
      headers: {
        Accept: 'application/oauth-authz-req+jwt, application/jwt',
      },
    });

    assert.equal(
      statusCode, 200,
      `unexpected request_uri response status code, expected 200 OK, got ${statusCode} ${STATUS_CODES[statusCode]}`,
    );

    cache.set(cacheKey, body);

    return body;
  }
}

module.exports = RequestUriCache;
