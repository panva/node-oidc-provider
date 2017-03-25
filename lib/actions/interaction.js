const url = require('url');
const compose = require('koa-compose');
const bodyParser = require('../shared/selective_body');
const views = require('../views');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function devInteractions(provider) {
  /* eslint-disable no-console, no-multi-str */
  console.info('NOTICE: a quick start development-only feature devInteractions is enabled, \
you are expected to disable these interactions and provide your own');
  /* eslint-enable */

  return {
    get: compose([
      async function interactionRender(ctx, next) {
        const details = provider.interactionDetails(ctx.req);
        const client = await provider.Client.find(details.params.client_id);
        ctx.assert(client, 400);

        const action = url.parse(ctx.oidc.urlFor('submit', { grant: details.uuid })).pathname;
        const view = (() => {
          switch (details.interaction.reason) {
            case 'consent_prompt':
            case 'client_not_authorized':
              return 'interaction';
            default:
              return 'login';
          }
        })();

        const locals = {
          action,
          client,
          returnTo: details.returnTo,
          params: details.params,
        };
        locals.body = views[view](locals);

        ctx.type = 'html';
        ctx.body = views.layout(locals);

        await next();
      },
    ]),
    post: compose([
      parseBody,
      async function interactionSubmit(ctx, next) {
        switch (ctx.oidc.body.view) { // eslint-disable-line default-case
          case 'login':
            provider.interactionFinished(ctx.req, ctx.res, {
              login: {
                account: ctx.oidc.body.login,
                acr: '1',
                remember: !!ctx.oidc.body.remember,
                ts: Math.floor(Date.now() / 1000),
              },
              consent: {},
            });
            break;
          case 'interaction':
            provider.interactionFinished(ctx.req, ctx.res, { consent: {} });
            break;
        }

        await next();
      },
    ]),
  };
};
