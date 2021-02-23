const { strict: assert } = require('assert');

module.exports = (provider) => (superclass) => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'sessionUid',
      'expiresWithSession',
    ];
  }

  static async find(...args) {
    const token = await super.find(...args);

    const ignoreSessionBinding = args[1] && args[1].ignoreSessionBinding === true;

    if (!token || !token.expiresWithSession || ignoreSessionBinding) {
      return token;
    }

    const session = await provider.Session.findByUid(token.sessionUid);
    try {
      assert(session, 'its related session was not found');

      // session is still for the same account
      assert.equal(token.accountId, session.accountId, 'token and session principal are now different');

      // session is still the same grantId
      assert.equal(token.grantId, session.grantIdFor(token.clientId), 'client\'s token and session grantId are now different');
    } catch (err) {
      return undefined;
    }

    return token;
  }
};
