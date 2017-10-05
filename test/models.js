const store = new Map();
const epochTime = require('../lib/helpers/epoch_time');

function grantKeyFor(id) {
  return ['grant', id].join(':');
}

class TestAdapter {
  constructor(name) {
    this.name = name;
    if (store.has(name)) return store.get(name);
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
    const grantId = store.get(key) && store.get(key).grantId;

    store.delete(key);

    if (grantId) {
      const grantKey = grantKeyFor(grantId);

      store.get(grantKey).forEach(token => store.delete(token));
    }

    return Promise.resolve();
  }

  consume(id) {
    store.get(this.key(id)).consumed = epochTime();
    return Promise.resolve();
  }

  syncFind(id) {
    return store.get(this.key(id));
  }

  find(id) {
    return Promise.resolve(this.syncFind(id));
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);

    const { grantId } = payload;
    if (grantId) {
      const grantKey = grantKeyFor(grantId);
      const grant = store.get(grantKey);
      if (!grant) {
        store.set(grantKey, [key]);
      } else {
        grant.push(key);
      }
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
