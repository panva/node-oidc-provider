const { difference, isEmpty } = require('lodash');
const { InvalidRequest } = require('../../helpers/errors');
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

    if (!isEmpty(unsupported)) {
      ctx.throw(new InvalidRequest(`invalid prompt value(s) provided. (${unsupported.join(',')})`));
    }

    if (prompts.includes('none') && prompts.length !== 1) {
      ctx.throw(new InvalidRequest('prompt none must only be used alone'));
    }
  }

  await next();
};
