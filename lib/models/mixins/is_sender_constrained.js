const x5t = 'x5t#S256';
const jkt = 'jkt#S256';

const { [x5t]: thumbprint } = require('../../helpers/calculate_thumbprint');

module.exports = (superclass) => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      x5t,
      jkt,
    ];
  }

  /* istanbul ignore next */
  setS256Thumbprint(cert) {
    // DEPRECATED/NOT USED
    this[x5t] = thumbprint(cert);
  }

  setThumbprint(prop, input) {
    switch (prop) {
      case 'x5t':
        this[x5t] = thumbprint(input);
        break;
      case 'jkt':
        this[jkt] = input.thumbprint;
        break;
      /* istanbul ignore next */
      default:
        throw new Error('unsupported');
    }
  }

  isSenderConstrained() {
    if (this[jkt] || this[x5t]) {
      return true;
    }

    return false;
  }

  get tokenType() {
    if (this[jkt]) {
      return 'DPoP';
    }

    return 'Bearer';
  }
};
