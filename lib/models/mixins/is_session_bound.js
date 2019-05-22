const assert = require('assert');

module.exports = provider => superclass => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'sessionUid',
      'expiresWithSession',
    ];
  }

  static async find(...args) {
    const token = await super.find(...args);
    if (!token || !token.expiresWithSession) {
      return token;
    }

    const session = await provider.Session.findByUid(token.sessionUid);
    try {
      assert(session);

      // session is still for the same account
      assert.deepEqual(token.accountId, session.accountId());

      // session is still the same grantId
      assert.deepEqual(token.grantId, session.grantIdFor(token.clientId));

      // session still has all the scopes
      const accepted = session.acceptedScopesFor(token.clientId);
      assert([...token.scopes].every(x => accepted.has(x)));
    } catch (err) {
      return undefined;
    }

    return token;
  }
};
