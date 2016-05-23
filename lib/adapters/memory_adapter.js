'use strict';

const LRU = require('lru-cache');

const client = new LRU({});

class MemoryAdapter {
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
    const grantId = client.get(key) && client.get(key).grantId;

    client.del(key);

    if (grantId) {
      const grantKey = this.grantKey(grantId);

      client.get(grantKey).forEach(token => client.del(token));
    }

    return Promise.resolve();
  }

  consume(id) {
    client.get(this.key(id)).consumed = Date.now() / 1000 | 0;
    return Promise.resolve();
  }

  find(id) {
    return Promise.resolve(client.get(this.key(id)));
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);

    const grantId = payload.grantId;
    if (grantId) {
      const grantKey = this.grantKey(grantId);
      const grant = client.get(grantKey);
      if (!grant) {
        client.set(grantKey, [key]);
      } else {
        grant.push(key);
      }
    }

    client.set(key, payload, expiresIn * 1000);

    return Promise.resolve();
  }
}

module.exports = MemoryAdapter;
