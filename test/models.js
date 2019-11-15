/* eslint-disable max-classes-per-file */

const map = new Map();

map.del = function (...args) {
  this.delete(...args);
};

const { expect } = require('chai');

const epochTime = require('../lib/helpers/epoch_time');
const MemoryAdapter = require('../lib/adapters/memory_adapter');

MemoryAdapter.setStorage(map);
const testStorage = new Map();

class TestAdapter extends MemoryAdapter {
  constructor(name) {
    if (testStorage.has(name)) return testStorage.get(name);
    super(name);
    this.store = map;
    testStorage.set(name, this);
  }

  static for(name) {
    if (testStorage.has(name)) return testStorage.get(name);
    return new this(name);
  }

  get(key) {
    return this.constructor.for(key);
  }

  static clear() {
    map.clear();
  }

  clear() { // eslint-disable-line class-methods-use-this
    map.clear();
  }

  syncFind(id) {
    return map.get(this.key(id)) || undefined;
  }

  syncUpdate(id, update) {
    const found = map.get(this.key(id));
    if (!found) return;
    Object.assign(found, update);
  }

  async upsert(id, payload, expiresIn) {
    if (this.model !== 'RegistrationAccessToken' && this.model !== 'InitialAccessToken' && this.model !== 'Client') {
      expect(payload).to.have.property('exp').that.is.a('number').and.is.finite;
      expect(payload.exp).to.be.closeTo(expiresIn + epochTime(), 1);
    }

    return super.upsert(id, payload, expiresIn);
  }
}

class Account {
  constructor(id) {
    this.accountId = id;
    testStorage.set(`Account:${this.accountId}`, this);
  }

  static get storage() {
    return testStorage;
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
      preferred_username: 'johnny',
      profile: 'https://johnswebsite.com',
      sub: this.accountId,
      updated_at: 1454704946,
      website: 'http://example.com',
      zoneinfo: 'Europe/Berlin',
    };
  }

  static async findAccount(ctx, id) {
    let acc = testStorage.get(`Account:${id}`);
    if (!acc) {
      acc = new Account(id);
    }
    return acc;
  }
}

module.exports = { Account, TestAdapter };
