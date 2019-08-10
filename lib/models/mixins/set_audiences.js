const ensureConform = require('../../helpers/ensure_conform');

module.exports = (superclass) => class extends superclass {
  setAudiences(audiences) {
    if (audiences) {
      const value = ensureConform(audiences);

      if (value.length) {
        this.aud = value;
      }
    }
  }
};
