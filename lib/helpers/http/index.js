/* istanbul ignore file */

const got = require('./got');

const httpWrapper = {
  useGot() {
    this.get = got.get;
    this.post = got.post;
  },
  useRequest() {
    const request = require('./request'); // eslint-disable-line global-require
    this.get = request.get;
    this.post = request.post;
  },
};

httpWrapper.useGot();

module.exports = httpWrapper;
