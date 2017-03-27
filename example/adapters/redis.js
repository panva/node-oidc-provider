const Redis = require('ioredis'); // eslint-disable-line import/no-unresolved
const { isEmpty } = require('lodash');

const client = new Redis(process.env.REDIS_URL, {
  keyPrefix: 'oidc:',
});

function grantKeyFor(id) {
  return `grant:${id}`;
}

class RedisAdapter {
  constructor(name) {
    this.name = name;
  }

  key(id) {
    return `${this.name}:${id}`;
  }

  async destroy(id) {
    const key = this.key(id);
    const grantId = await client.hget(key, 'grantId');
    const tokens = await client.lrange(grantKeyFor(grantId), 0, -1);
    const deletions = tokens.map(token => client.del(token));
    deletions.push(client.del(key));
    await deletions;
  }

  consume(id) {
    return client.hset(this.key(id), 'consumed', Math.floor(Date.now() / 1000));
  }

  async find(id) {
    const data = await client.hgetall(this.key(id));
    if (isEmpty(data)) {
      return undefined;
    } else if (data.dump !== undefined) {
      return JSON.parse(data.dump);
    }
    return data;
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);
    let toStore = payload;

    // Clients are not simple objects where value is always a string
    // redis does only allow string values =>
    // work around it to keep the adapter interface simple
    if (this.name === 'Client' || this.name === 'Session') {
      toStore = { dump: JSON.stringify(payload) };
    }

    const multi = client.multi();
    multi.hmset(key, toStore);

    if (expiresIn) {
      multi.expire(key, expiresIn);
    }

    if (toStore.grantId) {
      const grantKey = grantKeyFor(toStore.grantId);
      multi.rpush(grantKey, key);
    }

    return multi.exec();
  }
}

module.exports = RedisAdapter;
