module.exports = (superclass) => class extends superclass {
  static async revokeByGrantId(grantId) {
    await this.adapter.revokeByGrantId(grantId);
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'grantId',
    ];
  }
};
