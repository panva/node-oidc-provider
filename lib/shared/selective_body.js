const querystring = require('querystring');

const raw = require('raw-body');

const attention = require('../helpers/attention');
const { InvalidRequest } = require('../helpers/errors');

let warned;

async function selectiveBody(cty, ctx, next) {
  if (ctx.is(cty)) {
    try {
      let usedFallback;
      const body = await (() => {
        if (ctx.req.readable) {
          return raw(ctx.req, {
            length: ctx.length,
            limit: '56kb',
            encoding: ctx.charset,
          });
        }
        if (!warned) {
          warned = true;
          /* eslint-disable no-multi-str */
          attention.warn('already parsed request body detected, having upstream middleware parser \
is not recommended, resolving to use req.body or request.body instead');
          /* eslint-enable */
        }
        usedFallback = true;
        return ctx.req.body || ctx.request.body;
      })();

      if (body instanceof Buffer || typeof body === 'string') {
        if (cty === 'application/json') {
          ctx.oidc.body = JSON.parse(body);
        } else {
          ctx.oidc.body = querystring.parse(body.toString());
        }
      } else if (usedFallback && cty === 'application/x-www-form-urlencoded') {
        // get rid of possible upstream parsers that parse querystring with objects, arrays, etc
        ctx.oidc.body = querystring.parse(querystring.stringify(body));
      } else {
        ctx.oidc.body = body;
      }
    } catch (err) {
      throw new InvalidRequest('couldnt parse the request body');
    }

    await next();
  } else {
    throw new InvalidRequest(`only ${cty} content-type bodies are supported on ${ctx.method} ${ctx.path}`);
  }
}

Object.assign(selectiveBody, {
  json: selectiveBody.bind(undefined, 'application/json'),
  urlencoded: selectiveBody.bind(undefined, 'application/x-www-form-urlencoded'),
});

module.exports = selectiveBody;
