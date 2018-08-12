const base64url = require('base64url');

const epochTime = require('../lib/helpers/epoch_time');
const { formats: { default: FORMAT } } = require('../lib/helpers/defaults');

const store = new Map();

function grantKeyFor(id) {
  return ['grant', id].join(':');
}

function userCodeKeyFor(userCode) {
  return ['userCode', userCode].join(':');
}

class TestAdapter {
  constructor(name) {
    this.name = name;
    if (store.has(name)) return store.get(name);
    // ID-less model, only needed for tests
    store.set(name, this);
    this.store = store;
  }

  static for(name) {
    if (store.has(name)) return store.get(name);
    return new this(name);
  }

  get(key) {
    return this.constructor.for(key);
  }

  key(id) {
    return [this.name, id].join(':');
  }

  clear() { // eslint-disable-line class-methods-use-this
    store.clear();
  }

  destroy(id) {
    const key = this.key(id);

    const found = this.get(key);
    const grantId = found && found.grantId;

    store.delete(key);

    if (grantId) {
      const grantKey = grantKeyFor(grantId);
      store.get(grantKey).forEach(token => store.delete(token));
      store.delete(grantKey);
    }

    return Promise.resolve();
  }

  consume(id) {
    store.get(this.key(id)).consumed = epochTime();
    return Promise.resolve();
  }

  syncFind(id, { payload = false } = {}) {
    const found = store.get(this.key(id));
    if (!found) return undefined;
    if (payload && FORMAT === 'legacy') {
      return JSON.parse(base64url.decode(found.payload));
    }
    return found;
  }

  syncUpdate(id, update) {
    const found = store.get(this.key(id));
    if (!found) return;
    if (FORMAT === 'legacy') {
      const payload = JSON.parse(base64url.decode(found.payload));
      Object.assign(payload, update);
      found.payload = base64url(JSON.stringify(payload));
    } else {
      Object.assign(found, update);
    }
  }

  find(id) {
    return Promise.resolve(this.syncFind(id));
  }

  findByUserCode(userCode) {
    const id = store.get(userCodeKeyFor(userCode));
    return this.find(id);
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);

    const { grantId, userCode } = payload;
    if (grantId) {
      const grantKey = grantKeyFor(grantId);
      const grant = store.get(grantKey);
      if (!grant) {
        store.set(grantKey, [key]);
      } else {
        grant.push(key);
      }
    }

    if (userCode) {
      store.set(userCodeKeyFor(userCode), id, expiresIn * 1000);
    }

    store.set(key, payload, expiresIn * 1000);

    return Promise.resolve();
  }
}

class Account {
  constructor(id) {
    this.accountId = id;
    store.set(`Account:${this.accountId}`, this);
  }

  static get storage() {
    return store;
  }

  claims() {
    return {
      address: {
        country: '000',
        formatted: '000',
        locality: '000',
        postal_code: '000',
        region: '000',
        street_address: '000',
      },
      birthdate: '1987-10-16',
      email: 'johndoe@example.com',
      email_verified: false,
      family_name: 'Doe',
      gender: 'male',
      given_name: 'John',
      locale: 'en-US',
      middle_name: 'Middle',
      name: 'John Doe',
      nickname: 'Johny',
      phone_number: '+420 721 773500',
      phone_number_verified: false,
      picture: 'http://lorempixel.com/400/200/',
      preferred_username: 'Jdawg',
      profile: 'https://johnswebsite.com',
      sub: this.accountId,
      updated_at: 1454704946,
      website: 'http://example.com',
      zoneinfo: 'Europe/Berlin',
    };
  }

  static async findById(ctx, id) {
    let acc = store.get(`Account:${id}`);
    if (!acc) {
      acc = new Account(id);
    }
    return acc;
  }
}

module.exports = { Account, TestAdapter };
