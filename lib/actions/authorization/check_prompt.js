const { InvalidRequest } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Checks that all requested prompts are supported and validates prompt none is not combined with
 * other prompts
 *
 * @throws: invalid_request
 */
module.exports = function checkPrompt(ctx, next) {
  if (ctx.oidc.params.prompt !== undefined) {
    const { prompts } = ctx.oidc;
    const supported = instance(ctx.oidc.provider).configuration('prompts');

    for (const prompt of prompts) { // eslint-disable-line no-restricted-syntax
      if (!supported.has(prompt)) {
        throw new InvalidRequest('unsupported prompt value requested');
      }
    }

    if (prompts.has('none') && prompts.size !== 1) {
      throw new InvalidRequest('prompt none must only be used alone');
    }
  }

  return next();
};
