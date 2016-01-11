'use strict';

let _ = require('lodash');
let errors = require('../helpers/errors');

module.exports = function * getBearer(next) {
  let mechanisms = _.omitBy({
    body: _.get(this.request, 'body.access_token'),
    header: this.headers.authorization,
    query: this.query.access_token,
  }, _.isUndefined);

  this.assert(_.keys(mechanisms).length,
    new errors.InvalidTokenError());

  this.assert(_.keys(mechanisms).length === 1,
    new errors.InvalidRequestError(
      'bearer token must only be provided using one mechanism'));

  _.forEach(mechanisms, (value, mechanism) => {
    if (mechanism === 'header') {
      let parts = value.split(' ');

      this.assert(parts.length === 2 && parts[0] === 'Bearer',
        new errors.InvalidRequestError(
          'invalid authorization header value format'));

      this.oidc.bearer = parts[1];
    } else {
      this.oidc.bearer = value;
    }
  });

  yield next;
};
