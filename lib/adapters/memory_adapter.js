const LRU = require('lru-cache');

const epochTime = require('../helpers/epoch_time');

const storage = new LRU({});

function grantKeyFor(id) {
  return `grant:${id}`;
}

function userCodeKeyFor(userCode) {
  return `userCode:${userCode}`;
}

class MemoryAdapter {
  constructor(name) {
    this.name = name;
  }

  key(id) {
    return `${this.name}:${id}`;
  }

  destroy(id) {
    const key = this.key(id);

    const found = storage.get(key);
    const grantId = found && found.grantId;

    storage.del(key);

    if (grantId) {
      const grantKey = grantKeyFor(grantId);
      storage.get(grantKey).forEach(token => storage.del(token));
      storage.del(grantKey);
    }

    return Promise.resolve();
  }

  consume(id) {
    storage.get(this.key(id)).consumed = epochTime();
    return Promise.resolve();
  }

  find(id) {
    return Promise.resolve(storage.get(this.key(id)));
  }

  findByUserCode(userCode) {
    const id = storage.get(userCodeKeyFor(userCode));
    return this.find(id);
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);

    const { grantId, userCode } = payload;
    if (grantId) {
      const grantKey = grantKeyFor(grantId);
      const grant = storage.get(grantKey);
      if (!grant) {
        storage.set(grantKey, [key]);
      } else {
        grant.push(key);
      }
    }

    if (userCode) {
      storage.set(userCodeKeyFor(userCode), id, expiresIn * 1000);
    }

    storage.set(key, payload, expiresIn * 1000);

    return Promise.resolve();
  }

  static connect(provider) { // eslint-disable-line no-unused-vars
    // noop
  }
}

module.exports = MemoryAdapter;
