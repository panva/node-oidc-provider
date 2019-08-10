module.exports = (superclass) => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'gty',
    ];
  }
};
