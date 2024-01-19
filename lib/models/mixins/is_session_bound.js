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

    console.log('gio: token found:', JSON.stringify(token));
    console.log('gio: token found:', JSON.stringify(args));
    const ignoreSessionBinding = args[1] && args[1].ignoreSessionBinding === true;
    console.log('gio: ignoreSessionBinding:', ignoreSessionBinding);

    console.log('gio: token.expiresWithSession:', token.expiresWithSession);
    console.log('gio: ignoreSessionBinding:', ignoreSessionBinding);
    if (!token || !token.expiresWithSession || ignoreSessionBinding) {
      console.log('gio: returning token because token.expiresWithSession is false or ignoreSessionBinding is true');
      return token;
    }

    const session = await provider.Session.findByUid(token.sessionUid);
    console.log('gio: token.sessionUid:', token.sessionUid);
    console.log('gio: session found:', JSON.stringify(session));

    // related session was not found
    if (!session) {
      console.log('gio: returning undefined because session not found');
      return undefined;
    }

    // token and session principal are now different
    if (token.accountId !== session.accountId) {
      console.log('gio: returning undefined because token.accountId !== session.accountId');
      return undefined;
    }

    // token and session grantId are now different
    if (token.grantId !== session.grantIdFor(token.clientId)) {
      console.log('gio: returning undefined because token.grantId !== session.grantIdFor(token.clientId)');
      return undefined;
    }

    console.log('gio: returning token because all checks passed');
    return token;
  }
};
