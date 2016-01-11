'use strict';

let LRU = require('lru-cache');

let client = new LRU({});

class MemoryAdapter {
  constructor(name) {
    this.name = name;
  }

  key(id) {
    return [this.name, id].join(':');
  }

  grantKey(id) {
    return ['grant', id].join(':');
  }

  destroy(id) {
    let key = this.key(id);
    let grantId = client.get(key) && client.get(key).grantId;

    client.del(key);

    if (grantId) {
      let grantKey = this.grantKey(grantId);

      client.get(grantKey).forEach(key => {
        client.del(key);
      });
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
    let key = this.key(id);

    let grantId = payload.grantId;
    if (grantId) {
      let grantKey = this.grantKey(grantId);
      let grant = client.get(grantKey);
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
