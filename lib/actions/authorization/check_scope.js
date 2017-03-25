const _ = require('lodash');
const { InvalidRequestError } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
/*
 * Validates that all requested scopes are supported by the provider, that openid is amongst them
 * and that offline_access prompt is requested together with consent scope
 *
 * @throws: invalid_request
 */
module.exports = provider => async function checkScope(ctx, next) {
  const scopes = _.intersection(ctx.oidc.params.scope.split(' '), instance(provider).configuration('scopes'));
  const responseType = ctx.oidc.params.response_type;
  const prompts = ctx.oidc.prompts;

  const unsupported = _.difference(scopes, instance(provider).configuration('scopes'));
  ctx.assert(_.isEmpty(unsupported), new InvalidRequestError(
    `invalid scope value(s) provided. (${unsupported.join(',')})`));

  ctx.assert(scopes.indexOf('openid') !== -1,
    new InvalidRequestError('openid is required scope'));

  /*
   * Upon receipt of a scope parameter containing the offline_access value, the Authorization Server
   *
   * MUST ensure that the prompt parameter contains consent
   * MUST ignore the offline_access request unless the Client is using a response_type value that
   *  would result in an Authorization Code being returned,
   */

  if (scopes.indexOf('offline_access') !== -1) {
    if (!responseType.includes('code') || prompts.indexOf('consent') === -1) {
      _.pull(scopes, 'offline_access').join(' ');
    }
  }

  ctx.oidc.params.scope = scopes.join(' ');

  await next();
};
