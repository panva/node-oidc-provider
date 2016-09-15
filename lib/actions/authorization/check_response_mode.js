'use strict';

const _ = require('lodash');
const errors = require('../../helpers/errors');

const RESPONSE_MODES = {
  'code id_token token': 'fragment',
  'code id_token': 'fragment',
  'code token': 'fragment',
  code: 'query',
  'id_token token': 'fragment',
  id_token: 'fragment',
  none: 'query',
};

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 *
 * @throws: invalid_request
 */
module.exports = function* checkResponseMode(next) {
  const params = this.oidc.params;

  if (params.response_mode === undefined) {
    params.response_mode = _.get(RESPONSE_MODES, params.response_type, 'query');
  } else {
    const invalid = params.response_mode === 'query' && params.response_type.includes('token');

    this.assert(!invalid, new errors.InvalidRequestError(
      'response_mode not allowed for this response_type'));
  }


  yield next;
};
