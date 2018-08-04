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
 * options.retry {Number}
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

function requestWrap(method, url, {
  form,
  body,
  query,
  ...options
}) {
  if (form) {
    /* eslint-disable no-param-reassign */
    form = body;
    body = undefined;
    /* eslint-enable no-param-reassign */
  }
  return new Promise((resolve, reject) => {
    request({
      ...options,
      body,
      form,
      method,
      url,
      qs: query,
    }, (error, response, responseBody) => {
      if (error) {
        reject(error);
      } else {
        response.body = responseBody;
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
