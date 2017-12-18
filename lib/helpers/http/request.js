/* istanbul ignore file */

const http = require('http');
const request = require('request'); // eslint-disable-line import/no-unresolved, import/no-extraneous-dependencies

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

class HTTPError extends Error {
  constructor(response) {
    const statusMessage = http.STATUS_CODES[response.statusCode];
    super(`Response code ${response.statusCode} (${statusMessage})`, {});
    this.name = 'HTTPError';
    this.statusCode = response.statusCode;
    this.statusMessage = statusMessage;
    this.headers = response.headers;
    this.response = response;
  }
}

function requestWrap(method, url, options) {
  if (options.form) {
    /* eslint-disable no-param-reassign */
    options.form = options.body;
    options.body = undefined;
    /* eslint-enable no-param-reassign */
  }
  return new Promise((resolve, reject) => {
    request({
      method,
      url,
      headers: options.headers,
      qs: options.query,
      body: options.body,
      form: options.form,
      followRedirect: options.followRedirect,
      timeout: options.timeout,
    }, (error, response, body) => {
      if (error) {
        reject(error);
      } else {
        response.body = body;
        const { statusCode } = response;
        const limitStatusCode = options.followRedirect ? 299 : 399;

        if (statusCode !== 304 && (statusCode < 200 || statusCode > limitStatusCode)) {
          reject(new HTTPError(response));
          return;
        }

        resolve(response);
      }
    });
  });
}

module.exports = {
  get: function requestGet(url, options) {
    return requestWrap('GET', url, options);
  },
  post: function requestPost(url, options) {
    return requestWrap('POST', url, options);
  },
};
