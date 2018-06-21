const Redis = require('ioredis'); // eslint-disable-line import/no-unresolved
const { isEmpty } = require('lodash');

const client = new Redis(process.env.REDIS_URL, {
  keyPrefix: 'oidc:',
});

const grantable = [
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
];

function grantKeyFor(id) {
  return `grant:${id}`;
}

class RedisAdapter {
  constructor(name) {
    this.name = name;
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);
    const store = grantable.includes(this.name) ? {
      dump: JSON.stringify(payload),
      ...(payload.grantId ? { grantId: payload.grantId } : undefined),
    } : JSON.stringify(payload);

    const multi = client.multi();
    multi[grantable.includes(this.name) ? 'hmset' : 'set'](key, store);

    if (expiresIn) {
      multi.expire(key, expiresIn);
    }

    if (payload.grantId) {
      const grantKey = grantKeyFor(payload.grantId);
      multi.rpush(grantKey, key);
    }

    return multi.exec();
  }

  async find(id) {
    const data = grantable.includes(this.name) ?
      await client.hgetall(this.key(id)) :
      await client.get(this.key(id));

    if (isEmpty(data)) {
      return undefined;
    }

    if (typeof data === 'string') {
      return JSON.parse(data);
    }
    const { dump, ...rest } = data;
    return {
      ...rest,
      ...JSON.parse(dump),
    };
  }

  async destroy(id) {
    const key = this.key(id);
    const deletions = [];
    if (grantable.includes(this.name)) {
      const grantId = await client.hget(key, 'grantId');
      const tokens = await client.lrange(grantKeyFor(grantId), 0, -1);
      tokens.forEach(token => deletions.push(client.del(token)));
      deletions.push(client.del(grantKeyFor(grantId)));
    }
    deletions.push(client.del(key));
    await deletions;
  }

  consume(id) {
    return client.hset(this.key(id), 'consumed', Math.floor(Date.now() / 1000));
  }

  key(id) {
    return `${this.name}:${id}`;
  }
}

module.exports = RedisAdapter;
