'use strict';

let store = new Map();
let logins = new Map();
let uuid = require('node-uuid');

class Account {
  constructor() {
    this.accountId = uuid.v4();
    store.set(this.accountId, this);
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

  static findByLogin(login) {
    if (!logins.get(login)) {
      logins.set(login, new Account());
    }

    return Promise.resolve(logins.get(login));
  }

  static findById(id) {
    return Promise.resolve(store.get(id));
  }
}

module.exports = Account;
