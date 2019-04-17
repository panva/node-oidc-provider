const url = require('url');
const querystring = require('querystring');
const { inspect } = require('util');

const _ = require('lodash');

const attention = require('../helpers/attention');
const bodyParser = require('../shared/selective_body');
const views = require('../views');
const instance = require('../helpers/weak_cache');
const epochTime = require('../helpers/epoch_time');
const noCache = require('../shared/no_cache');

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');

const keys = new Set();
const dbg = obj => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  if (_.isEmpty(value)) return acc;
  acc[key] = inspect(value, { depth: null });
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${value}</strong>` : value; },
});

module.exports = function devInteractions(provider) {
  /* eslint-disable no-multi-str */
  attention.warn('a quick start development-only feature devInteractions is enabled, \
you are expected to disable these interactions and provide your own');
  /* eslint-enable */

  instance(provider).configuration().interactionUrl = async function interactionUrl(ctx) {
    return url.parse(ctx.oidc.urlFor('interaction', { uid: ctx.oidc.uid })).pathname;
  };

  return {
    render: [
      noCache,
      async function interactionRender(ctx, next) {
        const {
          uid, prompt, params, session,
        } = await provider.interactionDetails(ctx.req);
        const client = await provider.Client.find(params.client_id);

        let view;
        let title;

        switch (prompt.name) {
          case 'login':
            view = 'login';
            title = 'Sign-in';
            break;
          case 'consent':
            view = 'interaction';
            title = 'Authorize';
            break;
          default:
            ctx.throw(501, 'not implemented');
        }

        const locals = {
          client,
          uid,
          details: prompt.details,
          prompt: prompt.name,
          params,
          title,
          session: session ? dbg(session) : undefined,
          dbg: {
            params: dbg(params),
            prompt: dbg(prompt),
          },
        };

        locals.body = views[view](locals);

        ctx.type = 'html';
        ctx.body = views.layout(locals);

        await next();
      },
    ],
    abort: [
      noCache,
      function interactionAbort(ctx) {
        const result = {
          error: 'access_denied',
          error_description: 'End-User aborted interaction',
        };

        return provider.interactionFinished(ctx.req, ctx.res, result, {
          mergeWithLastSubmission: false,
        });
      },
    ],
    submit: [
      noCache,
      parseBody,
      async function interactionSubmit(ctx, next) {
        ctx.oidc.uid = ctx.params.uid;
        switch (ctx.oidc.body.prompt) { // eslint-disable-line default-case
          case 'login': {
            await provider.interactionFinished(ctx.req, ctx.res, {
              login: {
                account: ctx.oidc.body.login,
                ts: epochTime(),
              },
            }, {
              mergeWithLastSubmission: false,
            });
            break;
          }
          case 'consent': {
            const result = { consent: {} };
            await provider.interactionFinished(ctx.req, ctx.res, result, {
              mergeWithLastSubmission: true,
            });
            break;
          }
          default:
            ctx.throw(501, 'not implemented');
        }

        await next();
      },
    ],
  };
};
