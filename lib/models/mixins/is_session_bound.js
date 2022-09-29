export default (provider) => (superclass) => class extends superclass {
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

    // related session was not found
    if (!session) {
      return undefined;
    }

    // token and session principal are now different
    if (token.accountId !== session.accountId) {
      return undefined;
    }

    // token and session grantId are now different
    if (token.grantId !== session.grantIdFor(token.clientId)) {
      return undefined;
    }

    return token;
  }
};
