export default (provider) => class PreAuthorizedCode extends provider.BaseToken {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'consumed',
      'grantId',
      'accountId',
      'claims',
      'rar',
      'resource',
      'scope',
      'txCode',
    ];
  }

  async consume() {
    await this.adapter.consume(this.jti);
    this.emit('consumed');
  }

  get isValid() {
    return !this.consumed && !this.isExpired;
  }

  static async revokeByGrantId(grantId) {
    await this.adapter.revokeByGrantId(grantId);
  }
};
