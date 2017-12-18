/* istanbul ignore file */

const got = require('got');

/*
 * url {String}
 * options {Object}
 * options.headers {Object}
 * options.body {String|Object}
 * options.form {Boolean}
 * options.query {Object}
 * options.timeout {Number}
 * options.retries {Number}
 * options.followRedirect {Boolean}
 */
module.exports.get = function gotGet(url, options) {
  return got.get(url, options);
};

module.exports.post = function gotPost(url, options) {
  return got.post(url, options);
};
