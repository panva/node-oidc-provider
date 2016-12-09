'use strict';

const assert = require('assert');
const querystring = require('querystring');
const raw = require('raw-body');
const errors = require('../helpers/errors');

let warned;

module.exports = function getSelectiveBody(only) {
  assert(only, 'only must be provided');

  return function* selectiveBody(next) {
    if (this.is(only)) {
      try {
        const body = yield (() => {
          if (this.req.readable) {
            return raw(this.req, {
              length: this.length,
              limit: '56kb',
              encoding: this.charset,
            });
          }
          if (!warned) {
            warned = true;
            /* eslint-disable no-console */
            console.warn('already parsed request body detected, having upstream middleware parser is not recommended');
            console.warn('resolving to use req.body or request.body instead');
            /* eslint-enable no-console */
          }

          return Promise.resolve(this.req.body || this.request.body);
        })();

        if (body instanceof Buffer || typeof body === 'string') {
          if (only === 'application/json') {
            this.oidc.body = JSON.parse(body);
          } else {
            this.oidc.body = querystring.parse(String(body));
          }
        } else {
          this.oidc.body = body;
        }
      } catch (err) {
        this.throw(new errors.InvalidRequestError('couldnt parse the request body'));
      }

      yield next;
    } else {
      const msg = `only ${only} content-type ${this.method} bodies are supported`;
      this.throw(new errors.InvalidRequestError(msg));
    }
  };
};
