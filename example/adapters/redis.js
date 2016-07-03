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
    return client.hgetall(this.key(id)).then((data) => {
      if (_.isEmpty(data)) {
        return undefined;
      } else if (data.dump !== undefined) {
        return JSON.parse(data.dump);
      }
      return data;
    });
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);
    let toStore = payload;

    // Clients are not simple objects where value is always a string
    // redis does only allow string values =>
    // work around it to keep the adapter interface simple
    if (this.name === 'Client') {
      toStore = {
        dump: JSON.stringify(payload),
      };
    }

    const multi = client.multi();
    multi.hmset(key, toStore);

    if (expiresIn) {
      multi.expire(key, expiresIn);
    }

    if (toStore.grantId) {
      const grantKey = this.grantKey(toStore.grantId);
      multi.rpush(grantKey, key);
    }

    return multi.exec();
  }
}

module.exports = RedisAdapter;
