const url = require('url');
const compose = require('koa-compose');
const attention = require('../helpers/attention');
const bodyParser = require('../shared/selective_body');
const views = require('../views');
const instance = require('../helpers/weak_cache');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function devInteractions(provider) {
  /* eslint-disable no-multi-str */
  attention.info('a quick start development-only feature devInteractions is enabled, \
you are expected to disable these interactions and provide your own');
  /* eslint-enable */

  instance(provider).configuration().interactionUrl = async function interactionUrl(ctx) {
    return url.parse(ctx.oidc.urlFor('interaction', { grant: ctx.oidc.uuid })).pathname;
  };

  return {
    get: compose([
      async function interactionRender(ctx, next) {
        ctx.oidc.uuid = ctx.params.grant;
        const details = await provider.interactionDetails(ctx.req);
        const client = await provider.Client.find(details.params.client_id);
        ctx.assert(client, 400);

        const action = url.parse(ctx.oidc.urlFor('submit', { grant: details.uuid })).pathname;
        let view;
        switch (details.interaction.reason) {
          case 'consent_prompt':
          case 'client_not_authorized':
          case 'native_client_prompt':
            view = 'interaction';
            break;
          default:
            view = 'login';
        }

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
        ctx.oidc.uuid = ctx.params.grant;
        switch (ctx.oidc.body.view) { // eslint-disable-line default-case
          case 'login':
            await provider.interactionFinished(ctx.req, ctx.res, {
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
            await provider.interactionFinished(ctx.req, ctx.res, { consent: {} });
            break;
        }

        await next();
      },
    ]),
  };
};
