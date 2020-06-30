const { strict: assert } = require('assert');
const url = require('url');
const querystring = require('querystring');
const { inspect } = require('util');

const attention = require('../helpers/attention');
const { urlencoded: parseBody } = require('../shared/selective_body');
const views = require('../views');
const instance = require('../helpers/weak_cache');
const noCache = require('../shared/no_cache');
const { interactions: { url: defaultInteractionUri } } = require('../helpers/defaults')();

const keys = new Set();
const dbg = (obj) => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  acc[key] = inspect(value, { depth: null });
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${value}</strong>` : value; },
});

module.exports = function devInteractions(provider) {
  /* eslint-disable no-multi-str */
  attention.warn('a quick start development-only feature devInteractions is enabled, \
you are expected to disable these interactions and provide your own');

  const configuration = instance(provider).configuration('interactions');

  /* istanbul ignore if */
  if (configuration.url !== defaultInteractionUri) {
    attention.warn('you\'ve configured your own interactions.url but devInteractions are still enabled, \
your configuration is not in effect');
  }
  /* eslint-enable */

  instance(provider).configuration('interactions').url = async function interactionUrl(ctx) {
    return url.parse(ctx.oidc.urlFor('interaction', { uid: ctx.oidc.uid })).pathname;
  };

  return {
    render: [
      noCache,
      async function interactionRender(ctx, next) {
        const {
          uid, prompt, params, session,
        } = await provider.interactionDetails(ctx.req, ctx.res);
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
          abortUrl: ctx.oidc.urlFor('abort', { uid }),
          submitUrl: ctx.oidc.urlFor('submit', { uid }),
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
        const { prompt: { name } } = await provider.interactionDetails(ctx.req, ctx.res);
        switch (ctx.oidc.body.prompt) { // eslint-disable-line default-case
          case 'login': {
            assert.equal(name, 'login');
            await provider.interactionFinished(ctx.req, ctx.res, {
              login: { account: ctx.oidc.body.login },
            }, { mergeWithLastSubmission: false });
            break;
          }
          case 'consent': {
            assert.equal(name, 'consent');
            const result = { consent: {} };
            await provider.interactionFinished(ctx.req, ctx.res, result, {
              mergeWithLastSubmission: true,
            });
            break;
          }
          /* istanbul ignore next */
          default:
            ctx.throw(501, 'not implemented');
        }

        await next();
      },
    ],
  };
};
