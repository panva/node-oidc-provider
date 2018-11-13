module.exports = superclass => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'accountId',
      'acr',
      'amr',
      'authTime',
      'claims',
      'grantId',
      'nonce',
      'resource',
      'scope',
      'sid',
    ];
  }
};
