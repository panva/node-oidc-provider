'use strict';

const _ = require('lodash');
const uuid = require('uuid');
const assert = require('assert');
const epochTime = require('./helpers/epoch_time');
const instance = require('./helpers/weak_cache');

module.exports = class AdapterTest {
  constructor(provider, accountIdFactory, clientIdFactory) {
    this.provider = provider;
    const accountId = accountIdFactory || /* istanbul ignore next */ uuid;
    const clientId = clientIdFactory || /* istanbul ignore next */ uuid;

    this.data = {
      accountId: accountId(),
      acr: instance(provider).configuration('acrValues[0]'),
      authTime: epochTime(),
      claims: {
        id_token: {
          email: null,
          family_name: { essential: true },
          gender: { essential: false },
          given_name: { value: 'John' },
          locale: { values: ['en-US', 'en-GB'] },
          middle_name: {},
        },
      },
      clientId: clientId(),
      grantId: uuid(),
      nonce: String(Math.random()),
      redirectUri: 'http://client.example.com/cb',
      scope: 'openid profile',
    };
  }

  execute() {
    return this.authorizationCodeInsert()
      .then(this.authorizationCodeFind.bind(this))
      .then(this.authorizationCodeConsume.bind(this))
      .then(this.accessTokenSave.bind(this))
      .then(this.accessTokenFind.bind(this))
      .then(this.accessTokenDestroy.bind(this));
  }

  authorizationCodeInsert() {
    const ac = new (this.provider.AuthorizationCode)(this.data);
    return ac.save().then((saved) => {
      assert(saved, 'expected code to be saved');
      return saved;
    });
  }

  authorizationCodeFind(code) {
    this.ac = code;
    return this.provider.AuthorizationCode.find(code, {
      ignoreExpiration: true,
    }).then((found) => {
      this.code = found;
      assert(found, 'expected code to be found');
      assert(_.isMatch(found, this.data), 'expected stored values to match the original ones');
      return found;
    });
  }

  authorizationCodeConsume(code) {
    return code.consume().then(() => this.provider.AuthorizationCode.find(this.ac, {
      ignoreExpiration: true,
    })).then((found) => {
      assert(found.consumed, 'expected code to be consumed');
    });
  }

  accessTokenSave() {
    const at = new (this.provider.AccessToken)(
      _.pick(this.code, 'accountId', 'claims', 'clientId', 'grantId', 'scope'));
    return at.save().then((saved) => {
      assert(saved, 'expected access token to be saved');
      return saved;
    });
  }

  accessTokenFind(token) {
    this.token = token;
    return this.provider.AccessToken.find(token, {
      ignoreExpiration: true,
    }).then((found) => {
      assert(found, 'expected token to be found');
      return found;
    });
  }

  accessTokenDestroy(token) {
    return token.destroy().then(() => this.provider.AccessToken.find(this.token, {
      ignoreExpiration: true,
    })).then((found) => {
      assert(!found, 'expected token not to be found');
    })
    .then(() => this.provider.AuthorizationCode.find(this.ac, {
      ignoreExpiration: true,
    }))
    .then((found) => {
      assert(!found, 'expected authorization code not to be found');
    });
  }
};
