'use strict';

const store = new Map();

class TestAdapter {
  constructor(name) {
    this.name = name;
  }

  static get storage() {
    return store;
  }

  get storage() {
    return store;
  }

  key(id) {
    return [this.name, id].join(':');
  }

  grantKey(id) {
    return ['grant', id].join(':');
  }

  destroy(id) {
    const key = this.key(id);
    const grantId = store.get(key) && store.get(key).grantId;

    store.delete(key);

    if (grantId) {
      const grantKey = this.grantKey(grantId);

      store.get(grantKey).forEach(token => store.del(token));
    }

    return Promise.resolve();
  }

  consume(id) {
    store.get(this.key(id)).consumed = Date.now() / 1000 | 0;
    return Promise.resolve();
  }

  find(id) {
    return Promise.resolve(store.get(this.key(id)));
  }

  upsert(id, payload, expiresIn) {
    const key = this.key(id);

    const grantId = payload.grantId;
    if (grantId) {
      const grantKey = this.grantKey(grantId);
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

  get storage() {
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

  static findById(id) {
    let acc = store.get(`Account:${id}`);
    if (!acc) {
      acc = new Account(id);
    }
    return Promise.resolve(acc);
  }
}

module.exports = { Account, TestAdapter };
