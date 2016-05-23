/* istanbul ignore next */
'use strict';

const Redis = require('ioredis'); // eslint-disable-line import/no-unresolved
const _ = require('lodash');
const client = new Redis(process.env.REDIS_URL, {
  keyPrefix: 'oidc:',
});

class RedisAdapter {
  constructor(name) {
    this.name = name;
  }

  key(id) {
    return `${this.name}:${id}`;
  }

  grantKey(id) {
    return `grant:${id}`;
  }

  destroy(id) {
    const key = this.key(id);

    return client.hget(key, 'grantId')
    .then((grantId) => client.lrange(this.grantKey(grantId), 0, -1))
    .then((tokens) => Promise.all(_.map(tokens, (token) => client.del(token))))
    .then(() => client.del(key));
  }

  consume(id) {
    return client.hset(this.key(id), 'consumed', Date.now() / 1000 | 0);
  }

  find(id) {
    return client.hgetall(this.key(id)).then((some) => {
      if (_.isEmpty(some)) {
        return undefined;
      }
      return some;
    });
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);

    const multi = client.multi()
      .hmset(key, payload)
      .expire(key, expiresIn);

    const grantId = payload.grantId;
    if (grantId) {
      const grantKey = this.grantKey(grantId);
      multi.rpush(grantKey, key);
    }

    return multi.exec();
  }
}

module.exports = RedisAdapter;
