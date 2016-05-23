/* eslint-disable no-console, max-len */
'use strict';

const _ = require('lodash');
const uuid = require('uuid').v4;
const assert = require('assert');

class AdapterTest {
  constructor(provider, accountIdFactory, clientIdFactory) {
    this.accountId = accountIdFactory;
    this.clientId = clientIdFactory;
    this.provider = provider;
  }

  run() {
    const provider = this.provider;

    const ac = new provider.AuthorizationCode({
      accountId: this.accountId(),
      acr: provider.configuration.acrValues[0],
      authTime: new Date() / 1000 | 0,
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
      clientId: this.clientId(),
      grantId: uuid(),
      nonce: `${Math.random()}`,
      redirectUri: 'http://client.example.com/cb',
      scope: 'openid profile',
    });
    console.log('AuthorizationCode upsert()');
    let initialPromise;
    try {
      initialPromise = ac.toToken();
    } catch (err) {
      console.error(err);
      process.exit(1);
    }

    initialPromise.then((code) => {
      console.log('AuthorizationCode inserted');
      this.ac = code;
      console.log('AuthorizationCode find()');
      return provider.AuthorizationCode.find(code, {
        ignoreExpiration: true,
      });
    })
    .then((code) => {
      console.log('AuthorizationCode found');
      this.code = code;

      console.log('AuthorizationCode consume()');
      return code.consume();
    })
    .then(() => {
      console.log('AuthorizationCode consumed');
      return provider.AuthorizationCode.find(this.ac, {
        ignoreExpiration: true,
      });
    })
    .then((code) => {
      assert.ok(code.consumed, 'expected to find code');
      console.log('AuthorizationCode consumed PASS');
    })
    .then(() => {
      const at = new provider.AccessToken(_.pick(this.code, 'accountId', 'claims', 'clientId', 'grantId', 'scope'));
      console.log('AccessToken upsert()');

      return at.toToken();
    })
    .then((token) => {
      console.log('AccessToken inserted');
      this.at = token;
      console.log('AccessToken find()');
      return provider.AccessToken.find(token, {
        ignoreExpiration: true,
      });
    })
    .then((token) => {
      console.log('AccessToken found');
      this.token = token;

      console.log('AccessToken destroy()');
      return token.destroy();
    })
    .then(() => {
      console.log('AccessToken destroyed');
      console.log('AccessToken find() again');
      return provider.AccessToken.find(this.at, {
        ignoreExpiration: true,
      });
    })
    .then((token) => {
      assert.ok(!token, 'expected not to find token');
      console.log('AccessToken not found PASS');
    })
    .then(() => {
      console.log('AuthorizationCode find() again');
      return provider.AuthorizationCode.find(this.ac, {
        ignoreExpiration: true,
      });
    })
    .then((code) => {
      assert.ok(!code, 'expected not to find code');
      console.log('AuthorizationCode not found PASS');
    })
    .then(() => {
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
  }
}

module.exports = AdapterTest;
