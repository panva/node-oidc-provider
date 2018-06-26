module.exports = provider => superclass => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'consumed',
    ];
  }

  consume() {
    provider.emit('token.consumed', this);
    return this.adapter.consume(this.jti);
  }

  get isValid() {
    return !this.consumed && !this.isExpired;
  }
};
