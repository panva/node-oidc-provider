const assert = require('assert');

const { isMatch, pick } = require('lodash');
const uuid = require('uuid/v4');

const epochTime = require('./helpers/epoch_time');
const instance = require('./helpers/weak_cache');

module.exports = class AdapterTest {
  constructor(provider, accountId = uuid, clientId = uuid) {
    this.provider = provider;

    this.data = {
      accountId: accountId(),
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

  async execute() {
    await this.authorizationCodeInsert()
      .then(this.authorizationCodeFind.bind(this))
      .then(this.authorizationCodeConsume.bind(this))
      .then(this.accessTokenSave.bind(this))
      .then(this.accessTokenFind.bind(this))
      .then(this.accessTokenDestroy.bind(this));

    if (instance(this.provider).configuration('features.deviceCode')) {
      const dc = new (this.provider.DeviceCode)({
        clientId: this.data.clientId,
        grantId: this.data.grantId,
        userCode: '123-456-789',
        params: {
          client_id: 'client',
          scope: 'openid',
        },
      });

      await dc.save();
      const found = await this.provider.DeviceCode.findByUserCode('123-456-789', { ignoreExpiration: true });
      assert(found, 'expected device code to be found by user code');
    }
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
      assert(isMatch(found, this.data), 'expected stored values to match the original ones');
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
    const at = new (this.provider.AccessToken)(pick(this.code, 'accountId', 'claims', 'clientId', 'grantId', 'scope'));
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
