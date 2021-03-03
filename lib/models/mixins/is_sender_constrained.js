const x5t = 'x5t#S256';
const jkt = 'jkt';

const { [x5t]: thumbprint } = require('../../helpers/calculate_thumbprint');

module.exports = (superclass) => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      x5t,
      jkt,
    ];
  }

  setThumbprint(prop, input) {
    switch (prop) {
      case 'x5t':
        this[x5t] = thumbprint(input);
        break;
      case 'jkt':
        this[jkt] = input;
        break;
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
