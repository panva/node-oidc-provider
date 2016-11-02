'use strict';

const _ = require('lodash');
const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * If claims parameter is provided and supported handles it's validation
 * - should not be combined with rt none
 * - should be JSON serialized object with id_token or userinfo properties as objects
 * - claims.userinfo should not be used if authorization result is not access_token
 *
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 *
 * @throws: invalid_request
 */
module.exports = provider => function* checkClaims(next) {
  const params = this.oidc.params;

  if (params.claims !== undefined && instance(provider).configuration('features.claimsParameter')) {
    this.assert(params.response_type !== 'none', new errors.InvalidRequestError(
      'claims parameter should not be combined with response_type none'));

    const claims = (() => {
      try {
        return JSON.parse(params.claims);
      } catch (err) {
        return this.throw(new errors.InvalidRequestError('could not parse the claims parameter JSON'));
      }
    })();

    this.assert(_.isPlainObject(claims),
      new errors.InvalidRequestError('claims parameter should be a JSON object'));

    this.assert(claims.userinfo !== undefined || claims.id_token !== undefined,
      new errors.InvalidRequestError(
        'claims parameter should have userinfo or id_token properties'));

    this.assert(claims.userinfo === undefined || _.isPlainObject(claims.userinfo),
      new errors.InvalidRequestError('claims.userinfo should be an object'));

    this.assert(claims.id_token === undefined || _.isPlainObject(claims.id_token),
      new errors.InvalidRequestError('claims.id_token should be an object'));

    this.assert(params.response_type !== 'id_token' || !claims.userinfo,
      new errors.InvalidRequestError(
        'claims.userinfo should not be used if access_token is not issued'));

    this.oidc.claims = claims;
  }

  if (params.max_age || this.oidc.client.requireAuthTime) {
    _.merge(this.oidc.claims, { id_token: { auth_time: { essential: true } } });
  }

  const acrValues = params.acr_values;

  if (acrValues) {
    _.merge(this.oidc.claims, { id_token: { acr: { values: acrValues.split(' ') } } });
  }

  yield next;
};
