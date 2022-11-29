import bodyParser from './selective_body.js';

export default async function parseBodyIfPost(cty, ctx, next) {
  if (ctx.method === 'POST') {
    await bodyParser(cty, ctx, next);
  } else {
    await next();
  }
}
