'use strict';

const bodyParser = require('../shared/selective_body');

module.exports = function getConditionalBody(only) {
  const parseBody = bodyParser(only);

  return async function parseBodyIfPost(ctx, next) {
    if (ctx.method === 'POST') {
      await parseBody(ctx, next);
    } else {
      await next();
    }
  };
};
