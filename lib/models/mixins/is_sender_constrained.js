import { InvalidRequest } from '../../helpers/errors.js';
import certificateThumbprint from '../../helpers/certificate_thumbprint.js';

const x5t = 'x5t#S256';
const jkt = 'jkt';

export default (superclass) => class extends superclass {
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
        if (this[jkt]) {
          throw new InvalidRequest('multiple proof-of-posession mechanisms are not allowed');
        }
        this[x5t] = certificateThumbprint(input);
        break;
      case 'jkt':
        if (this[x5t]) {
          throw new InvalidRequest('multiple proof-of-posession mechanisms are not allowed');
        }
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
