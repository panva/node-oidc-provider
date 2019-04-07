/* istanbul ignore file */

const got = require('./got');

const httpWrapper = {
  useGot() {
    this.get = got.get;
    this.post = got.post;
  },
};

module.exports = httpWrapper;
