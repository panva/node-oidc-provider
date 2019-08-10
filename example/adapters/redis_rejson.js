/*
 * requires Redis ReJSON plugin (https://oss.redislabs.com/rejson/)
 */

// npm i ioredis@^4.0.0
const Redis = require('ioredis'); // eslint-disable-line import/no-unresolved

const client = new Redis(process.env.REDIS_URL);

function grantKeyFor(id) {
  return `oidc:grant:${id}`;
}

function userCodeKeyFor(userCode) {
  return `oidc:userCode:${userCode}`;
}

function uidKeyFor(uid) {
  return `oidc:uid:${uid}`;
}

class RedisAdapter {
  constructor(name) {
    this.name = name;
  }

  async upsert(id, payload, expiresIn) {
    const key = this.key(id);

    const multi = client.multi();

    multi.call('JSON.SET', key, '.', JSON.stringify(payload));

    if (expiresIn) {
      multi.expire(key, expiresIn);
    }

    if (payload.grantId) {
      const grantKey = grantKeyFor(payload.grantId);
      multi.rpush(grantKey, key);
      // if you're seeing grant key lists growing out of acceptable proportions consider using LTRIM
      // here to trim the list to an appropriate length
      const ttl = await client.ttl(grantKey);
      if (expiresIn > ttl) {
        multi.expire(grantKey, expiresIn);
      }
    }

    if (payload.userCode) {
      const userCodeKey = userCodeKeyFor(payload.userCode);
      multi.set(userCodeKey, id);
      multi.expire(userCodeKey, expiresIn);
    }

    if (payload.uid) {
      const uidKey = uidKeyFor(payload.uid);
      multi.set(uidKey, id);
      multi.expire(uidKey, expiresIn);
    }

    await multi.exec();
  }

  async find(id) {
    const key = this.key(id);
    const data = await client.call('JSON.GET', key);
    if (!data) return undefined;
    return JSON.parse(data);
  }

  async findByUid(uid) {
    const id = await client.get(uidKeyFor(uid));
    return this.find(id);
  }

  async findByUserCode(userCode) {
    const id = await client.get(userCodeKeyFor(userCode));
    return this.find(id);
  }

  async destroy(id) {
    const key = this.key(id);
    await client.del(key);
  }

  async revokeByGrantId(grantId) { // eslint-disable-line class-methods-use-this
    const multi = client.multi();
    const tokens = await client.lrange(grantKeyFor(grantId), 0, -1);
    tokens.forEach((token) => multi.del(token));
    multi.del(grantKeyFor(grantId));
    await multi.exec();
  }

  async consume(id) {
    await client.call('JSON.SET', this.key(id), 'consumed', Math.floor(Date.now() / 1000));
  }

  key(id) {
    return `oidc:${this.name}:${id}`;
  }
}

module.exports = RedisAdapter;
