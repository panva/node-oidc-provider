const { difference, isEmpty } = require('lodash');
const { InvalidRequestError } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Checks that all requested prompts are supported and validates prompt none is not combined with
 * other prompts
 *
 * @throws: invalid_request
 */
module.exports = provider => async function checkPrompt(ctx, next) {
  if (ctx.oidc.params.prompt !== undefined) {
    const { prompts } = ctx.oidc;
    const unsupported = difference(prompts, instance(provider).configuration('prompts'));

    ctx.assert(isEmpty(unsupported), new InvalidRequestError(
      `invalid prompt value(s) provided. (${unsupported.join(',')})`));

    ctx.assert(!prompts.includes('none') || prompts.length === 1,
      new InvalidRequestError('prompt none must only be used alone'));
  }

  await next();
};
