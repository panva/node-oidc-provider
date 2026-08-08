import * as querystring from 'node:querystring';

import * as attention from '../helpers/attention.js';
import { InvalidRequest } from '../helpers/errors.js';

let warned;

const LIMIT = 56 * 1024;

/*
 * Reads the request body with a hard byte cap. Every throw here is caught below
 * and re-thrown as InvalidRequest, so the distinctions raw-body drew between
 * 413, 415 and 400 were already collapsed before this replaced it.
 *
 * The iterator must not destroy the request on an early return - the error
 * response still has to be written to the socket.
 */
async function readBody(req, length, charset) {
  if (req.readableEncoding) {
    throw new Error('stream encoding should not be set');
  }

  if (length !== undefined && length > LIMIT) {
    throw new Error('request entity too large');
  }

  const chunks = [];
  let received = 0;

  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    received += chunk.length;
    if (received > LIMIT) {
      throw new Error('request entity too large');
    }
    if (length !== undefined && received > length) {
      throw new Error('request size did not match content length');
    }
    chunks.push(chunk);
  }

  if (length !== undefined && received !== length) {
    throw new Error('request size did not match content length');
  }

  const body = Buffer.concat(chunks, received);

  return charset ? new TextDecoder(charset).decode(body) : body;
}

async function selectiveBody(cty, ctx, next) {
  if (ctx.is(cty)) {
    try {
      let usedFallback;
      const body = await (() => {
        if (ctx.req.readable) {
          return readBody(ctx.req, ctx.request.length, ctx.charset);
        }
        if (!warned) {
          warned = true;
          attention.warn('already parsed request body detected, having upstream middleware parser \
is not recommended, resolving to use req.body or request.body instead');
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
    } catch (cause) {
      throw new InvalidRequest('failed to parse the request body', undefined, { cause });
    }

    await next();
  } else if (ctx.get('content-type')) {
    throw new InvalidRequest(`only ${cty} content-type bodies are supported on ${ctx.method} ${ctx.path}`);
  } else {
    ctx.oidc.body = {};
    await next();
  }
}

export default selectiveBody;
export const json = selectiveBody.bind(undefined, 'application/json');
export const urlencoded = selectiveBody.bind(undefined, 'application/x-www-form-urlencoded');
