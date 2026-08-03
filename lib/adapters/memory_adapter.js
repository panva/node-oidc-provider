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

function storageOptions(expiresIn, clockTolerance) {
  if (typeof expiresIn === 'number') {
    return { maxAge: (expiresIn + clockTolerance) * 1000 };
  }
  return undefined;
}

function getGrantMembers(store, grantId) {
  const stored = store.get(grantKeyFor(grantId));
  if (stored instanceof Map) {
    return stored;
  }
  return new Map([...stored ?? []].map((key) => [key, Infinity]));
}

function setGrantMembers(store, grantId, members) {
  const now = Date.now();
  for (const [key, expiresAt] of members) {
    if (expiresAt <= now) {
      members.delete(key);
    }
  }

  const grantKey = grantKeyFor(grantId);
  if (members.size === 0) {
    store.delete(grantKey);
    return;
  }

  const expiresAt = Math.max(...members.values());
  const options = Number.isFinite(expiresAt) ? { maxAge: expiresAt - now } : undefined;
  store.set(grantKey, members, options);
}

function removeSecondaryIndexes(store, id, payload) {
  if (payload.uid && store.get(sessionUidKeyFor(payload.uid)) === id) {
    store.delete(sessionUidKeyFor(payload.uid));
  }
  if (payload.userCode && store.get(userCodeKeyFor(payload.userCode)) === id) {
    store.delete(userCodeKeyFor(payload.userCode));
  }
}

function removeIndexes(store, model, id, key, payload) {
  removeSecondaryIndexes(store, id, payload);

  if (grantable.has(model) && payload.grantId) {
    const members = getGrantMembers(store, payload.grantId);
    members.delete(key);
    setGrantMembers(store, payload.grantId, members);
  }
}

class MemoryAdapter {
  constructor(model, store, clockTolerance = 0) {
    this.model = model;
    this.store = store;
    this.clockTolerance = clockTolerance;
  }

  get storage() {
    return this.store ?? storage;
  }

  key(id) {
    return `${this.model}:${id}`;
  }

  async destroy(id) {
    const key = this.key(id);
    const payload = this.storage.get(key);
    this.storage.delete(key);
    if (payload) {
      removeIndexes(this.storage, this.model, id, key, payload);
    }
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
    const options = storageOptions(expiresIn, this.clockTolerance);
    const previous = this.storage.get(key);

    if (previous) {
      removeIndexes(this.storage, this.model, id, key, previous);
    }

    if (this.model === 'Session') {
      this.storage.set(sessionUidKeyFor(payload.uid), id, options);
    }

    const { grantId, userCode } = payload;
    if (grantable.has(this.model) && grantId) {
      const members = getGrantMembers(this.storage, grantId);
      const expiresAt = typeof expiresIn === 'number'
        ? Date.now() + ((expiresIn + this.clockTolerance) * 1000)
        : Infinity;
      members.set(key, expiresAt);
      setGrantMembers(this.storage, grantId, members);
    }

    if (userCode) {
      this.storage.set(userCodeKeyFor(userCode), id, options);
    }

    this.storage.set(key, payload, options);
  }

  async revokeByGrantId(grantId) {
    const grantKey = grantKeyFor(grantId);
    const members = getGrantMembers(this.storage, grantId);
    if (members.size) {
      for (const token of members.keys()) {
        const payload = this.storage.get(token);
        this.storage.delete(token);
        if (payload) {
          const id = payload.jti ?? token.slice(token.indexOf(':') + 1);
          removeSecondaryIndexes(this.storage, id, payload);
        }
      }
      this.storage.delete(grantKey);
    }
  }
}

export default MemoryAdapter;
export function createMemoryAdapter(clockTolerance = 0) {
  const store = createStorage();
  return (model) => new MemoryAdapter(model, store, clockTolerance);
}
export function setStorage(store) { storage = store; }
