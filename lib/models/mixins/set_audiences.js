const ensureConform = require('../../helpers/ensure_conform');

module.exports = superclass => class extends superclass {
  setAudiences(audiences) {
    const { clientId } = this;
    if (audiences) {
      const value = ensureConform(audiences, clientId);

      if (value.length > 1) {
        this.aud = value;
      }
    }
  }
};
