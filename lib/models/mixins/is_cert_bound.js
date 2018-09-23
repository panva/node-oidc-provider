const digest = require('../../helpers/calculate_thumbprint');

module.exports = superclass => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'x5t#S256',
    ];
  }

  setS256Thumbprint(cert) {
    this['x5t#S256'] = digest(cert);
  }
};
