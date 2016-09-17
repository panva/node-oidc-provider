'use strict';

const errors = require('../../helpers/errors');

const ALLOWED = ['plain', 'S256'];

/*
 * assign default code_challenge_method if a code_challenge is provided
 * check presence of code code_challenge if code_challenge_method is provided
 */
module.exports = function* checkPixy(next) {
  const params = this.oidc.params;

  if (params.code_challenge_method) {
    this.assert(ALLOWED.indexOf(params.code_challenge_method) !== -1,
      new errors.InvalidRequestError('not supported value of code_challenge_method'));

    this.assert(params.code_challenge,
      new errors.InvalidRequestError('code_challenge must be provided with code_challenge_method'));
  }

  if (!params.code_challenge_method && params.code_challenge) {
    params.code_challenge_method = 'plain';
  }

  yield next;
};
