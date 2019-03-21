const bodyParser = require('./selective_body');

module.exports = async function parseBodyIfPost(cty, ctx, next) {
  if (ctx.method === 'POST') {
    await bodyParser(cty, ctx, next);
  } else {
    await next();
  }
};
