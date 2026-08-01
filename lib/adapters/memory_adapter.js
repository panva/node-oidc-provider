import QuickLRU from 'quick-lru';

import epochTime from '../helpers/epoch_time.js';

function createStorage() {
  return new QuickLRU({ maxSize: 1000 });
}

let storage = createStorage();

function grantKeyFor(id) {
  return `grant:${id}`;
}

function sessionUidKeyFor(id) {
  return `sessionUid:${id}`;
}

function userCodeKeyFor(userCode) {
  return `userCode:${userCode}`;
}

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
  'PreAuthorizedCode',
]);

class MemoryAdapter {
  constructor(model, store) {
    this.model = model;
    this.store = store;
  }

  get storage() {
    return this.store ?? storage;
  }

  key(id) {
    return `${this.model}:${id}`;
  }

  async destroy(id) {
    const key = this.key(id);
    this.storage.delete(key);
  }

  async consume(id) {
    this.storage.get(this.key(id)).consumed = epochTime();
  }

  async find(id) {
    return this.storage.get(this.key(id));
  }

  async findByUid(uid) {
    const id = this.storage.get(sessionUidKeyFor(uid));
    return this.find(id);
  }

  async findByUserCode(userCode) {
    const id = this.storage.get(userCodeKeyFor(userCode));
    return this.find(id);
  }

  async upsert(id, payload, expiresIn) {
    const key = this.key(id);
    const options = { maxAge: expiresIn * 1000 };

    if (this.model === 'Session') {
      this.storage.set(sessionUidKeyFor(payload.uid), id, options);
    }

    const { grantId, userCode } = payload;
    if (grantable.has(this.model) && grantId) {
      const grantKey = grantKeyFor(grantId);
      const grant = this.storage.get(grantKey);
      if (!grant) {
        this.storage.set(grantKey, [key]);
      } else {
        grant.push(key);
      }
    }

    if (userCode) {
      this.storage.set(userCodeKeyFor(userCode), id, options);
    }

    this.storage.set(key, payload, options);
  }

  async revokeByGrantId(grantId) {
    const grantKey = grantKeyFor(grantId);
    const grant = this.storage.get(grantKey);
    if (grant) {
      grant.forEach((token) => { this.storage.delete(token); });
      this.storage.delete(grantKey);
    }
  }
}

export default MemoryAdapter;
export function createMemoryAdapter() {
  const store = createStorage();
  return (model) => new MemoryAdapter(model, store);
}
export function setStorage(store) { storage = store; }
